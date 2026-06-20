/**
 * Alerts Routes — durable (table `alerts`, via services/alertsStore).
 *
 * Replaces the in-memory alertStore. Response shapes are unchanged (the row is a
 * superset of the old object); `source` / `type` / `read` are new optional
 * filters. The list + unread-count read paths degrade to empty if the table
 * isn't migrated yet, so they never 500 an existing client.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { alertsQueue } from '../queues';
import { requireAuth, requireRole } from '../middleware/auth';
import { NotFoundError } from '../lib/errors';
import { AlertListFilterSchema, CreateAlertSchema, UpdateAlertSchema, EvaluateAlertSchema, AlertEscalateSchema } from '../lib/schemas';
import { escInt } from '../lib/sanitize';
import { createLogger } from '../lib/logger';
import {
    listAlerts, unreadCounts, alertFacets, getAlert, insertAlert, alertExistsForIoc,
    markRead, markAllRead, acknowledge, bulkAcknowledge, deleteAlert, updateAlert, escalateAlert,
} from '../services/alertsStore';

const log = createLogger('Alerts');
const alerts = new Hono();

/**
 * GET /v1/alerts — list with pagination + filters (severity / source / type / read|unread).
 */
alerts.get('/', requireAuth, async (c) => {
    const { page, pageSize: limit, severity, source, type, unread, read } = AlertListFilterSchema.parse(c.req.query());
    let items: Awaited<ReturnType<typeof listAlerts>>['items'] = [];
    let total = 0;
    try {
        ({ items, total } = await listAlerts({ page, limit, severity, source, type, unread, read }));
    } catch (err) {
        // Degrade to empty rather than 500 if the table isn't migrated yet.
        log.warn('alerts list failed — returning empty', { err: String(err) });
    }
    return c.json({
        success: true,
        data: { alerts: items, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
    });
});

/**
 * GET /v1/alerts/unread/count — badge counts.
 */
alerts.get('/unread/count', async (c) => {
    let counts = { unread: 0, highSeverity: 0 };
    try { counts = await unreadCounts(); } catch (err) { log.warn('alert count failed — returning 0', { err: String(err) }); }
    return c.json({ success: true, data: { ...counts, timestamp: new Date().toISOString() } });
});

/**
 * GET /v1/alerts/facets — distinct source/type values + counts (server-side faceting).
 */
alerts.get('/facets', requireAuth, async (c) => {
    let facets = { sources: [] as { value: string; count: number }[], types: [] as { value: string; count: number }[] };
    try { facets = await alertFacets(); } catch (err) { log.warn('alert facets failed', { err: String(err) }); }
    return c.json({ success: true, data: facets });
});

/**
 * POST /v1/alerts/:id/read
 */
alerts.post('/:id/read', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    if (!(await markRead(id))) throw new NotFoundError('Alert', id);
    return c.json({ success: true, data: { alertId: id, read: true } });
});

/**
 * POST /v1/alerts/read-all
 */
alerts.post('/read-all', requireAuth, async (c) => {
    const markedRead = await markAllRead();
    return c.json({ success: true, data: { markedRead } });
});

/**
 * POST /v1/alerts — queue an alert (the worker persists it).
 */
alerts.post('/', requireAuth, async (c) => {
    const body = await c.req.json();
    const { severity, type, title, message, source, metadata } = CreateAlertSchema.parse(body);
    const job = await alertsQueue.add('manual-alert', { severity, type, title, message, source: source || 'manual', metadata });
    return c.json({ success: true, data: { jobId: job.id, severity, title, status: 'queued' } });
});

/**
 * PUT /v1/alerts/:id
 */
alerts.put('/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const updates = UpdateAlertSchema.parse(await c.req.json());
    const row = await updateAlert(id, updates);
    if (!row) throw new NotFoundError('Alert', id);
    return c.json({ success: true, data: row });
});

/**
 * DELETE /v1/alerts/:id
 */
alerts.delete('/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    if (!(await deleteAlert(id))) throw new NotFoundError('Alert', id);
    return c.json({ success: true, message: 'Alert deleted', data: { id } });
});

/**
 * POST /v1/alerts/:id/acknowledge
 */
alerts.post('/:id/acknowledge', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    if (!(await acknowledge(id))) throw new NotFoundError('Alert', id);
    return c.json({ success: true, data: { alertId: id, acknowledged: true } });
});

/**
 * POST /v1/alerts/evaluate — create alerts from high-risk IOCs.
 */
alerts.post('/evaluate', requireAuth, async (c) => {
    const { threshold } = EvaluateAlertSchema.parse(await c.req.json().catch(() => ({})));

    const { rawQuery } = await import('@rinjani/db');
    const result = await rawQuery(
        `SELECT id, type, value, risk_score, source, threat_type
         FROM iocs WHERE risk_score >= ${escInt(threshold)}
         ORDER BY risk_score DESC LIMIT 50`,
    );
    const rows = (result.rows || []) as Array<{ id: string; value: string; type: string; risk_score: number; source?: string; threat_type?: string }>;
    let created = 0;

    for (const ioc of rows) {
        if (await alertExistsForIoc(ioc.id)) continue;
        const severity = ioc.risk_score >= 90 ? 'critical' : ioc.risk_score >= 80 ? 'high' : 'medium';
        await insertAlert({
            type: 'high_risk_ioc',
            severity,
            title: `High-Risk IOC Detected: ${ioc.value}`,
            message: `IOC ${ioc.value} (${ioc.type}) has a composite risk score of ${ioc.risk_score}. Source: ${ioc.source || 'unknown'}. Threat type: ${ioc.threat_type || 'unknown'}.`,
            source: 'scoring-engine',
            metadata: { iocId: ioc.id, iocValue: ioc.value, iocType: ioc.type, riskScore: ioc.risk_score, threshold },
        });
        created++;
    }
    return c.json({ success: true, data: { evaluated: rows.length, alertsCreated: created, threshold } });
});

/**
 * POST /v1/alerts/:id/escalate (TheHive-inspired)
 */
alerts.post('/:id/escalate', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = AlertEscalateSchema.parse(await c.req.json().catch(() => ({})));
    const row = await escalateAlert(id, {
        priority: body.priority,
        escalatedBy: c.get('user')?.id || 'unknown',
        assignee: body.assignee || undefined,
        notes: body.notes || undefined,
        tags: body.tags,
    });
    if (!row) throw new NotFoundError('Alert', id);
    return c.json({ success: true, data: { alertId: id, escalated: true, priority: body.priority, assignee: body.assignee } });
});

/**
 * POST /v1/alerts/bulk-acknowledge
 */
alerts.post('/bulk-acknowledge', requireAuth, async (c) => {
    const { ids } = z.object({ ids: z.array(z.string().min(1)).min(1).max(500) }).parse(await c.req.json().catch(() => ({})));
    const acknowledged = await bulkAcknowledge(ids);
    return c.json({ success: true, data: { requested: ids.length, acknowledged } });
});

export default alerts;
