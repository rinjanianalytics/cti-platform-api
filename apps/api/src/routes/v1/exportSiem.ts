/**
 * SIEM exporters + direct push — Phase 4 #2.
 *
 *   POST /v1/export/cef         → CEF lines, one per IOC
 *   POST /v1/export/leef        → LEEF v2 lines
 *   POST /v1/export/ecs         → NDJSON in Elastic Common Schema
 *   POST /v1/siem/push/splunk   → ship the same data to Splunk HEC
 *   POST /v1/siem/push/elastic  → ship the same data via Elastic _bulk
 *
 * The codecs live in `@rinjani/core/siemFormatters`; the push clients
 * live in `../../services/siemPush/*`. Routes are the DB-query +
 * serve / fan-out glue.
 */
import { Hono } from 'hono';
import { requireAuth } from '../../middleware/auth';
import { rawQuery, sql } from '@rinjani/db';
import { SiemExportSchema, SiemPushSchema } from '../../lib/schemas';
import { createLogger } from '../../lib/logger';
import {
    toCefBatch, toLeefBatch, toEcs, ecsToNdjson,
    type SiemIOC,
} from '@rinjani/core/siemFormatters';
import { pushToSplunk } from '../../services/siemPush/splunkHec';
import { pushToElastic } from '../../services/siemPush/elasticBulk';
import { recordSiemExport } from '../../services/signalFunnel';

const log = createLogger('SIEMExport');
const exportSiem = new Hono();
exportSiem.use('*', requireAuth);

const userId = (c: { get: (k: 'user') => { id?: string } | undefined }) => c.get('user')?.id ?? null;

async function fetchIocs(filters: { dateFrom?: string; dateTo?: string; severity?: string; type?: string; limit: number }): Promise<SiemIOC[]> {
    const wheres: string[] = ['1=1'];
    const esc = (s: string) => s.replace(/'/g, "''");
    if (filters.dateFrom) wheres.push(`created_at >= '${esc(filters.dateFrom)}'`);
    if (filters.dateTo) wheres.push(`created_at <= '${esc(filters.dateTo)}'`);
    if (filters.severity) wheres.push(`severity = '${esc(filters.severity)}'`);
    if (filters.type) wheres.push(`type = '${esc(filters.type)}'`);
    const rows = await rawQuery<{
        id: string; type: string; value: string;
        threat_type: string | null; severity: string | null;
        confidence: number | null; source: string | null;
        tags: string[] | null;
        first_seen: string | null; last_seen: string | null;
    }>(sql.raw(`
        SELECT id, type, value, threat_type, severity, confidence, source, tags, first_seen, last_seen
        FROM iocs
        WHERE ${wheres.join(' AND ')}
        ORDER BY COALESCE(last_seen, created_at) DESC
        LIMIT ${filters.limit}
    `));
    return (rows.rows ?? []).map(r => ({
        id: r.id,
        type: r.type,
        value: r.value,
        threatType: r.threat_type,
        severity: r.severity,
        confidence: r.confidence,
        source: r.source,
        tags: r.tags,
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
    }));
}

exportSiem.post('/export/cef', async (c) => {
    const body = SiemExportSchema.parse(await c.req.json().catch(() => ({})));
    const iocs = await fetchIocs(body);
    const body_ = toCefBatch(iocs);
    log.info('CEF export', { count: iocs.length });
    await recordSiemExport({ format: 'cef', channel: 'export', recordCount: iocs.length, status: 'success', userId: userId(c) });
    return new Response(body_, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `attachment; filename="rinjani_cef_${Date.now()}.log"`,
            'X-Rinjani-Record-Count': String(iocs.length),
        },
    });
});

exportSiem.post('/export/leef', async (c) => {
    const body = SiemExportSchema.parse(await c.req.json().catch(() => ({})));
    const iocs = await fetchIocs(body);
    const body_ = toLeefBatch(iocs);
    log.info('LEEF export', { count: iocs.length });
    await recordSiemExport({ format: 'leef', channel: 'export', recordCount: iocs.length, status: 'success', userId: userId(c) });
    return new Response(body_, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `attachment; filename="rinjani_leef_${Date.now()}.log"`,
            'X-Rinjani-Record-Count': String(iocs.length),
        },
    });
});

exportSiem.post('/export/ecs', async (c) => {
    const body = SiemExportSchema.parse(await c.req.json().catch(() => ({})));
    const iocs = await fetchIocs(body);
    const ndjson = ecsToNdjson(iocs.map(toEcs));
    log.info('ECS NDJSON export', { count: iocs.length });
    await recordSiemExport({ format: 'ecs', channel: 'export', recordCount: iocs.length, status: 'success', userId: userId(c) });
    return new Response(ndjson, {
        status: 200,
        headers: {
            'Content-Type': 'application/x-ndjson; charset=utf-8',
            'Content-Disposition': `attachment; filename="rinjani_ecs_${Date.now()}.ndjson"`,
            'X-Rinjani-Record-Count': String(iocs.length),
        },
    });
});

// ── Direct push (Phase 4 #2 closer) ─────────────────────────────────

exportSiem.post('/siem/push/splunk', async (c) => {
    const body = SiemPushSchema.parse(await c.req.json().catch(() => ({})));
    const iocs = await fetchIocs(body);
    const result = await pushToSplunk(iocs, {
        index: body.index,
        sourcetype: body.sourcetype,
    });
    log.info('Splunk HEC push', { batchSize: result.batchSize, accepted: result.accepted, ok: result.ok });
    await recordSiemExport({ format: 'splunk', channel: 'push', destination: body.index ?? null, recordCount: result.accepted ?? result.batchSize ?? iocs.length, status: result.ok ? 'success' : 'failed', userId: userId(c) });
    return c.json({ success: result.ok, data: result }, result.ok ? 200 : 502);
});

exportSiem.post('/siem/push/elastic', async (c) => {
    const body = SiemPushSchema.parse(await c.req.json().catch(() => ({})));
    const iocs = await fetchIocs(body);
    const result = await pushToElastic(iocs, { index: body.index });
    log.info('Elastic _bulk push', { batchSize: result.batchSize, indexed: result.indexed, errorCount: result.errors.length, ok: result.ok });
    await recordSiemExport({ format: 'elastic', channel: 'push', destination: body.index ?? null, recordCount: result.indexed ?? result.batchSize ?? iocs.length, status: result.ok ? 'success' : 'failed', userId: userId(c) });
    return c.json({ success: result.ok, data: result }, result.ok ? 200 : 502);
});

export default exportSiem;
