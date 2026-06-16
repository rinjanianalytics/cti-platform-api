/**
 * SIEM inbound search adapter (AA.5 / PLAN Phase 10) — the read-only twin of
 * the shipped outbound SIEM push.
 *
 * A thin, query-validated, read-only `_search` client against Elastic /
 * OpenSearch (both speak the same `_search` API). BYO-endpoint — no SIEM is
 * bundled; the operator sets SIEM_URL (+ optional SIEM_INDEX, SIEM_API_KEY).
 * Until SIEM_URL is set the tool is an inert placeholder that fails gracefully,
 * so it ships now and lights up the moment a SIEM is deployed.
 *
 * Guards (PLAN Phase 10, mirroring isReadOnlyCypher): read-only `_search` only,
 * a closed denylist rejecting non-read operations, size-capped, time-bounded.
 * The orchestrator is HITL for writes; this fires a bounded read query.
 */

import { createLogger } from '../lib/logger';

const log = createLogger('SiemSearch');

export function isSiemConfigured(): boolean {
    return !!process.env.SIEM_URL;
}

export interface SiemSearchResult {
    total: number;
    hits: Record<string, unknown>[];
    tookMs: number;
    index: string;
}

// Defense-in-depth: `_search` is already read-only, but reject query strings
// that smell like a non-read op or a resource-abuse vector.
const UNSAFE_RE = /(_delete_by_query|_update_by_query|\bscript\b|\bpipeline\b|\bscroll\b)/i;

interface EsHit { _source?: Record<string, unknown> }
interface EsResponse {
    took?: number;
    hits?: { total?: { value?: number } | number; hits?: EsHit[] };
}

export async function siemSearch(opts: {
    query: string;
    index?: string;
    size?: number;
    sinceHours?: number;
}): Promise<SiemSearchResult> {
    const base = process.env.SIEM_URL;
    if (!base) {
        throw new Error('SIEM not configured — set SIEM_URL (an Elastic/OpenSearch _search endpoint) to enable telemetry hunting');
    }
    if (UNSAFE_RE.test(opts.query)) {
        throw new Error('query rejected: only read-only _search queries are allowed');
    }

    const index = opts.index || process.env.SIEM_INDEX || 'logs-*';
    const size = Math.min(Math.max(opts.size ?? 20, 1), 100);
    const must: Record<string, unknown>[] = [{ query_string: { query: opts.query } }];
    if (opts.sinceHours) {
        must.push({ range: { '@timestamp': { gte: `now-${Math.min(opts.sinceHours, 720)}h` } } });
    }
    const body = {
        size,
        query: { bool: { must } },
        sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }],
    };

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (process.env.SIEM_API_KEY) headers.Authorization = `ApiKey ${process.env.SIEM_API_KEY}`;

    const url = `${base.replace(/\/$/, '')}/${encodeURIComponent(index)}/_search`;
    const res = await fetch(url, {
        method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
        throw new Error(`SIEM ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    const d = (await res.json()) as EsResponse;
    const total = typeof d.hits?.total === 'object' ? (d.hits.total.value ?? 0) : (d.hits?.total ?? 0);
    const hits = (d.hits?.hits ?? []).map((h) => h._source ?? {});
    log.info('SIEM search', { index, query: opts.query.slice(0, 80), total });
    return { total, hits, tookMs: d.took ?? 0, index };
}

export const __testing = { UNSAFE_RE };
