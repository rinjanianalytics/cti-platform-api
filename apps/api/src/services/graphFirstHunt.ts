/**
 * Graph-first SIEM hunt (PLAN Track-B B3 / Phase 9–10) — a DETERMINISTIC
 * orchestration of shipped parts, distinct from the open-ended ReAct agent.
 *
 * The invariant: consult the threat graph BEFORE touching external telemetry.
 *
 *   1. EXPAND  — NL→Cypher (shipped) scopes + expands an indicator set from Neo4j
 *   2. SYNTH   — build a read-only Lucene query from those indicators
 *   3. HUNT    — siemSearch (shipped, read-only + validated) fires it at the SIEM
 *   4. CORRELATE — report which graph indicators actually appear in telemetry
 *
 * Guards: every step is READ-ONLY. The graph read can't mutate; the SIEM client
 * is `_search`-only with a denylist; nothing writes to hypotheses here (staging
 * evidence is a separate, explicit HITL action). Fallbacks never block the hunt:
 * an empty graph degrades to the caller's seed indicators; an unconfigured SIEM
 * returns the synthesized query + a clear "not configured" rather than failing.
 */
import { nlToCypherQuery } from './nlCypher';
import { siemSearch, isSiemConfigured } from './siemSearch';
import { createLogger } from '../lib/logger';

const log = createLogger('GraphFirstHunt');

export interface HuntRequest {
    question: string;
    seedIndicators?: string[];
    index?: string;
    sinceHours?: number;
    size?: number;
}

export interface HuntResult {
    question: string;
    graph: {
        cypher: string;
        recordCount: number;
        indicators: string[];
        usedFallback: boolean;   // graph had no signal → fell back to seed indicators
        error?: string;
    };
    siem: {
        configured: boolean;
        query?: string;
        total?: number;
        hitCount?: number;
        hits?: Record<string, unknown>[];
        index?: string;
        tookMs?: number;
        error?: string;
    };
    correlated: string[];        // graph indicators that appear in the telemetry hits
}

// ── indicator extraction ────────────────────────────────────────────────────
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
const URL = /^https?:\/\/\S{3,}$/i;
const ASSET_EXT = /\.(?:png|jpe?g|gif|svg|css|js|html?|json|woff2?)$/i;

function looksLikeIndicator(s: string): boolean {
    return IPV4.test(s) || HASH.test(s) || URL.test(s) || (DOMAIN.test(s) && !ASSET_EXT.test(s));
}

function collectStrings(v: unknown, out: string[], depth = 0): void {
    if (depth > 4 || out.length > 5000) return;
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) for (const x of v) collectStrings(x, out, depth + 1);
    else if (v && typeof v === 'object') for (const x of Object.values(v)) collectStrings(x, out, depth + 1);
}

/** Pull indicator-shaped values (IP/domain/hash/URL) out of arbitrary Cypher rows. */
export function extractIndicators(records: Record<string, unknown>[], cap = 50): string[] {
    const strings: string[] = [];
    for (const r of records) collectStrings(r, strings);
    const seen = new Set<string>();
    const out: string[] = [];
    for (const raw of strings) {
        const t = raw.trim();
        const key = t.toLowerCase();
        if (looksLikeIndicator(t) && !seen.has(key)) {
            seen.add(key);
            out.push(t);
            if (out.length >= cap) break;
        }
    }
    return out;
}

/** OR the indicators as quoted literals — query_string searches every field. */
export function synthesizeSiemQuery(indicators: string[]): string {
    return indicators.map((i) => `"${i.replace(/["\\]/g, '')}"`).join(' OR ');
}

function correlate(indicators: string[], hits: Record<string, unknown>[]): string[] {
    const blob = hits.map((h) => JSON.stringify(h).toLowerCase()).join('\n');
    return indicators.filter((i) => blob.includes(i.toLowerCase()));
}

const dedupe = (xs: string[]) => [...new Set(xs.map((x) => x.trim()).filter(Boolean))];

export async function graphFirstHunt(req: HuntRequest): Promise<HuntResult> {
    // 1. Graph-first expansion.
    const nl = await nlToCypherQuery(req.question, { limit: 100 });
    let indicators = extractIndicators(nl.records);
    let usedFallback = false;

    // 2. Fallback to caller seeds when the graph has no signal — never block.
    if (indicators.length === 0 && req.seedIndicators?.length) {
        indicators = dedupe(req.seedIndicators).slice(0, 50);
        usedFallback = true;
    }

    const graph: HuntResult['graph'] = {
        cypher: nl.cypher,
        recordCount: nl.records.length,
        indicators,
        usedFallback,
        error: nl.success ? undefined : nl.error,
    };
    log.info('graph-first hunt expand', { question: req.question.slice(0, 80), recordCount: nl.records.length, indicators: indicators.length, usedFallback });

    // 3. Nothing to hunt — stop honestly.
    if (indicators.length === 0) {
        return { question: req.question, graph, siem: { configured: isSiemConfigured() }, correlated: [] };
    }

    // 4. Synthesize the read-only telemetry query.
    const query = synthesizeSiemQuery(indicators);

    // 5. Fire it (or report the SIEM isn't wired yet — the query is still useful).
    if (!isSiemConfigured()) {
        return { question: req.question, graph, siem: { configured: false, query }, correlated: [] };
    }
    try {
        const r = await siemSearch({ query, index: req.index, size: req.size ?? 50, sinceHours: req.sinceHours ?? 168 });
        return {
            question: req.question,
            graph,
            siem: { configured: true, query, total: r.total, hitCount: r.hits.length, hits: r.hits.slice(0, 25), index: r.index, tookMs: r.tookMs },
            correlated: correlate(indicators, r.hits),
        };
    } catch (err) {
        return { question: req.question, graph, siem: { configured: true, query, error: (err as Error).message }, correlated: [] };
    }
}

export const __testing = { extractIndicators, synthesizeSiemQuery, looksLikeIndicator };
