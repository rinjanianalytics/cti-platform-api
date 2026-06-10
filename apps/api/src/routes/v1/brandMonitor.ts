/**
 * Brand / typo-squat monitoring routes — Phase 5 #1.
 *
 *   POST   /v1/brand/domains              Add an apex to the watchlist
 *   GET    /v1/brand/domains              List the watchlist
 *   GET    /v1/brand/domains/:id           Detail with recent alerts
 *   PATCH  /v1/brand/domains/:id           Toggle enabled / update label/owner
 *   DELETE /v1/brand/domains/:id           Remove from watchlist (cascades alerts)
 *   POST   /v1/brand/domains/:id/sweep    Run a sweep for one apex now
 *   POST   /v1/brand/sweep                Run a sweep across all enabled apexes
 *   GET    /v1/brand/alerts               Triage queue (filterable + ordered by score)
 *   PATCH  /v1/brand/alerts/:id            Analyst lifecycle (new → triaging → benign/escalated/blocked)
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    MonitoredDomainCreateSchema, MonitoredDomainUpdateSchema,
    BrandAlertListSchema, BrandAlertUpdateSchema,
} from '../../lib/schemas';
import { db, eq, and, desc, sql } from '@rinjani/db';
import { monitoredDomains, brandAlerts } from '@rinjani/db/schema';
import { sweepMonitoredDomain, sweepAllMonitoredDomains } from '../../services/brandMonitor';
import { createLogger } from '../../lib/logger';

const log = createLogger('BrandRoutes');
const router = new Hono();

// ── Watchlist CRUD ────────────────────────────────────────────────

router.post('/brand/domains', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = MonitoredDomainCreateSchema.parse(await c.req.json());
    const userId = c.get('user')?.id || 'unknown';
    try {
        const [row] = await db.insert(monitoredDomains).values({
            apexDomain: body.apexDomain,
            label: body.label ?? null,
            owner: body.owner ?? null,
            enabled: body.enabled,
            createdBy: userId,
        }).returning();
        log.info('Monitored domain added', { id: row.id, apex: row.apexDomain });
        return c.json({ success: true, data: row }, 201);
    } catch (err) {
        const e = err as { code?: string; message?: string };
        if (e.code === '23505') {
            return c.json({
                success: false,
                error: { code: 'CONFLICT', message: `apex "${body.apexDomain}" already monitored` },
            }, 409);
        }
        throw err;
    }
});

router.get('/brand/domains', requireAuth, async (c) => {
    const rows = await db.select().from(monitoredDomains).orderBy(monitoredDomains.apexDomain);
    return c.json({ success: true, data: rows });
});

router.get('/brand/domains/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const [row] = await db.select().from(monitoredDomains).where(eq(monitoredDomains.id, id)).limit(1);
    if (!row) throw new NotFoundError('Monitored domain', id);
    // Recent alerts (top 20 by score) for the detail view.
    const recent = await db.select().from(brandAlerts)
        .where(eq(brandAlerts.monitoredDomainId, id))
        .orderBy(desc(brandAlerts.score), desc(brandAlerts.lastCheckedAt))
        .limit(20);
    return c.json({ success: true, data: { ...row, recentAlerts: recent } });
});

router.patch('/brand/domains/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = MonitoredDomainUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.label !== undefined) patch.label = body.label;
    if (body.owner !== undefined) patch.owner = body.owner;
    if (body.enabled !== undefined) patch.enabled = body.enabled;
    const [row] = await db.update(monitoredDomains).set(patch).where(eq(monitoredDomains.id, id)).returning();
    if (!row) throw new NotFoundError('Monitored domain', id);
    return c.json({ success: true, data: row });
});

router.delete('/brand/domains/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id')!;
    const result = await db.delete(monitoredDomains).where(eq(monitoredDomains.id, id)).returning({ id: monitoredDomains.id });
    if (result.length === 0) throw new NotFoundError('Monitored domain', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// ── Sweep ─────────────────────────────────────────────────────────

router.post('/brand/domains/:id/sweep', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    try {
        const summary = await sweepMonitoredDomain(id);
        return c.json({ success: true, data: summary });
    } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes('not found')) throw new NotFoundError('Monitored domain', id);
        throw err;
    }
});

router.post('/brand/sweep', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const summaries = await sweepAllMonitoredDomains();
    return c.json({
        success: true,
        data: {
            domainsSwept: summaries.length,
            totalPermutations: summaries.reduce((acc, s) => acc + s.permutationsGenerated, 0),
            totalHitsCreated: summaries.reduce((acc, s) => acc + s.hitsCreated, 0),
            totalHitsUpdated: summaries.reduce((acc, s) => acc + s.hitsUpdated, 0),
            summaries,
        },
    });
});

// ── Triage queue ──────────────────────────────────────────────────

router.get('/brand/alerts', requireAuth, async (c) => {
    const f = BrandAlertListSchema.parse(c.req.query());
    const conds = [];
    if (f.monitoredDomainId) conds.push(eq(brandAlerts.monitoredDomainId, f.monitoredDomainId));
    if (f.status) conds.push(eq(brandAlerts.status, f.status));
    if (f.dnsState) conds.push(eq(brandAlerts.dnsState, f.dnsState));
    if (typeof f.minScore === 'number') conds.push(sql`${brandAlerts.score} >= ${f.minScore}`);
    const where = conds.length === 0 ? undefined : conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select().from(brandAlerts)
            .where(where ?? sql`true`)
            .orderBy(desc(brandAlerts.score), desc(brandAlerts.lastCheckedAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(brandAlerts).where(where ?? sql`true`),
    ]);
    return c.json({
        success: true,
        data: {
            items,
            pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
        },
    });
});

router.patch('/brand/alerts/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = BrandAlertUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.status !== undefined) patch.status = body.status;
    if (body.notes !== undefined) patch.notes = body.notes;
    const [row] = await db.update(brandAlerts).set(patch).where(eq(brandAlerts.id, id)).returning();
    if (!row) throw new NotFoundError('Brand alert', id);
    return c.json({ success: true, data: row });
});

export default router;
