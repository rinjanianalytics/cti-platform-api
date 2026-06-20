/**
 * Signal funnel — the ingest→action pipeline counts in one place, shared by the
 * REST `/v1/stats/funnel` route and the GraphQL `signalFunnel` resolver.
 *
 *   ingested   Σ feed_sync_runs.items_ingested  (cumulative upstream throughput)
 *   indicators COUNT(iocs)                       (deduped, excl. CVEs)
 *   correlated non-IOC entities (actors+malware+tools+vulns+techniques)
 *   validated  critical IOCs + critical vulns
 *   actioned   Σ siem_export_logs.record_count WHERE channel='push'  (pushed to SIEM)
 *
 * Counts that depend on optional tables (techniques, siem_export_logs) are read
 * defensively so a fresh/partly-migrated DB can't 500 the whole funnel.
 */
import { db, rawQuery, sql, siemExportLogs, type NewSiemExportLogRow } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('SignalFunnel');

export interface SignalFunnelCounts {
    ingested: number;
    indicators: number;
    correlated: number;
    validated: number;
    actioned: number;
}

const num = (v: unknown) => Number(v ?? 0);

async function safeCount(query: string): Promise<number> {
    try {
        const res = await rawQuery<{ n: string }>(sql.raw(query));
        return num(res.rows?.[0]?.n);
    } catch {
        return 0;
    }
}

export async function computeSignalFunnel(): Promise<SignalFunnelCounts> {
    // Always-present tables in one round-trip.
    const res = await rawQuery<{ ingested: string; indicators: string; correlated_base: string; validated: string }>(sql.raw(`
        SELECT
            (SELECT COALESCE(SUM(items_ingested), 0) FROM feed_sync_runs)                AS ingested,
            (SELECT COUNT(*) FROM iocs WHERE type != 'cve')                              AS indicators,
            (
                (SELECT COUNT(*) FROM threat_actors) + (SELECT COUNT(*) FROM malware) +
                (SELECT COUNT(*) FROM tools)         + (SELECT COUNT(*) FROM vulnerabilities)
            )                                                                            AS correlated_base,
            (
                (SELECT COUNT(*) FROM iocs WHERE severity = 'critical' AND type != 'cve') +
                (SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical')
            )                                                                            AS validated
    `));
    const r = res.rows?.[0] ?? ({} as Record<string, unknown>);

    // Optional tables, isolated so a missing one degrades to 0 instead of throwing.
    const techniques = await safeCount(`SELECT COUNT(*) AS n FROM techniques`);
    const actioned = await safeCount(`SELECT COALESCE(SUM(record_count), 0) AS n FROM siem_export_logs WHERE status = 'success' AND channel = 'push'`);

    return {
        ingested: num(r.ingested),
        indicators: num(r.indicators),
        correlated: num(r.correlated_base) + techniques,
        validated: num(r.validated),
        actioned,
    };
}

/** Record an export/push (best-effort — never block the response on the audit row). */
export async function recordSiemExport(entry: NewSiemExportLogRow): Promise<void> {
    try {
        await db.insert(siemExportLogs).values(entry);
    } catch (err) {
        log.warn('failed to record SIEM export', { err: String(err) });
    }
}
