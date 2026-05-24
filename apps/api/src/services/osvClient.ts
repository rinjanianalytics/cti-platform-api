/**
 * OSV (Open Source Vulnerabilities) client — primary CVE enrichment source.
 *
 *   - Public API at https://api.osv.dev — no auth, no rate limit
 *   - Covers most OSS CVEs (kernel, npm, pypi, go, rubygems, …) + many
 *     commercial advisories aggregated by Google
 *   - Returns OSV-format vulnerabilities. The CVSS score itself is given
 *     as a *vector string* (`CVSS:3.1/AV:N/...`) — we compute the
 *     numeric base score inline using the CVSS v3.1 specification.
 *
 * Used by `cveEnrichmentWorker.ts` and `vulnerabilityEnrichment.ts`:
 * try OSV first, fall back to NVD if OSV doesn't know the CVE.
 *
 * The Cloudflare bot challenge on NIST's developer portal makes NVD API
 * keys hard to obtain; OSV bypasses that entirely.
 */

import { createLogger } from '../lib/logger';

const log = createLogger('OSV');

const OSV_API_BASE = 'https://api.osv.dev/v1';
const TIMEOUT_MS = 15_000;

export interface CveEnrichmentData {
    cvss?: { score: number; severity: string; vector: string };
    published?: Date;
    lastModified?: Date;
    /** Which source served this enrichment, for observability. */
    source: 'osv' | 'nvd';
}

// ============================================================================
// CVSS v3 base-score calculator
// ============================================================================
// Implements the CVSS v3.0 / v3.1 base-score formula verbatim from
// https://www.first.org/cvss/v3.1/specification-document
//
// Returns null if the vector is malformed or missing required metrics —
// the worker treats that as "no CVSS available, try the next source".

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };

export function computeCvssV3Score(vector: string): number | null {
    if (!vector.startsWith('CVSS:3.')) return null;
    const parts = vector.split('/').slice(1);
    const m: Record<string, string> = {};
    for (const p of parts) {
        const [k, v] = p.split(':');
        if (k && v) m[k] = v;
    }

    const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    if (required.some(k => !m[k])) return null;

    const av = AV[m.AV];
    const ac = AC[m.AC];
    const ui = UI[m.UI];
    const c = CIA[m.C];
    const i = CIA[m.I];
    const a = CIA[m.A];
    const scopeChanged = m.S === 'C';
    const pr = scopeChanged ? PR_C[m.PR] : PR_U[m.PR];

    if ([av, ac, ui, c, i, a, pr].some(v => v == null)) return null;

    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    const impact = scopeChanged
        ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
        : 6.42 * iss;
    const exploitability = 8.22 * av * ac * pr * ui;

    let baseScore: number;
    if (impact <= 0) {
        baseScore = 0;
    } else if (scopeChanged) {
        baseScore = Math.min(1.08 * (impact + exploitability), 10);
    } else {
        baseScore = Math.min(impact + exploitability, 10);
    }
    // Round up to nearest 0.1 per spec (ceiling, not standard rounding).
    return Math.ceil(baseScore * 10) / 10;
}

export function cvssSeverityForScore(score: number): 'critical' | 'high' | 'medium' | 'low' | 'none' {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    if (score > 0) return 'low';
    return 'none';
}

// ============================================================================
// OSV API client
// ============================================================================

interface OsvSeverity {
    type: 'CVSS_V3' | 'CVSS_V2' | string;
    score: string;  // OSV stores the *vector string* in this field, not a numeric score
}

interface OsvVulnerability {
    id: string;
    summary?: string;
    details?: string;
    published?: string;
    modified?: string;
    severity?: OsvSeverity[];
    aliases?: string[];
}

/**
 * Look up a single CVE in OSV. Returns null if OSV doesn't have it (the
 * caller should fall back to NVD). Picks the highest-version CVSS metric
 * (v3.1 > v3.0 > v2) when multiple are present.
 */
export async function fetchFromOsv(cveId: string): Promise<CveEnrichmentData | null> {
    const id = cveId.toUpperCase().trim();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);

    let response: Response;
    try {
        response = await fetch(`${OSV_API_BASE}/vulns/${encodeURIComponent(id)}`, {
            signal: ctrl.signal,
            headers: { 'Accept': 'application/json' },
        });
    } catch (err) {
        log.debug('OSV fetch failed', { cveId: id, error: (err as Error).message });
        return null;
    } finally {
        clearTimeout(timer);
    }

    // OSV returns 404 for unknown CVEs — totally expected for proprietary
    // / Microsoft / Oracle CVEs that OSV doesn't index.
    if (response.status === 404) return null;
    if (!response.ok) {
        log.warn('OSV non-OK response', { cveId: id, status: response.status });
        return null;
    }

    let vuln: OsvVulnerability;
    try {
        vuln = await response.json() as OsvVulnerability;
    } catch {
        return null;
    }

    // Prefer CVSS_V3 over V2. OSV may return multiple severity entries.
    const severities = vuln.severity ?? [];
    const v3 = severities.find(s => s.type === 'CVSS_V3' && typeof s.score === 'string');
    const v2 = severities.find(s => s.type === 'CVSS_V2' && typeof s.score === 'string');

    let cvss: CveEnrichmentData['cvss'] | undefined;
    if (v3) {
        const score = computeCvssV3Score(v3.score);
        if (score != null) {
            cvss = {
                score,
                severity: cvssSeverityForScore(score),
                vector: v3.score,
            };
        }
    } else if (v2) {
        // CVSS v2 vectors are rare today; we don't implement the v2
        // formula. Skip — the caller's NVD fallback will pick this up.
        log.debug('OSV returned CVSS v2 only, deferring to NVD', { cveId: id });
    }

    return {
        cvss,
        published: vuln.published ? new Date(vuln.published) : undefined,
        lastModified: vuln.modified ? new Date(vuln.modified) : undefined,
        source: 'osv',
    };
}
