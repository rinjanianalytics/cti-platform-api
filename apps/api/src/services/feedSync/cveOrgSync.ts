/**
 * CVE.org cvelistV5 sync — primary CVE ingest source.
 *
 * MITRE's authoritative CVE list lives in a public GitHub repo
 * (`CVEProject/cvelistV5`). Every CNA-published CVE lands here within
 * minutes of disclosure — typically *days to weeks before* NVD surfaces
 * it (NVD's analyst backlog has been 5-14 days through 2024-2026).
 *
 * Sync strategy:
 *
 *   1. Pull `cves/delta.json` — a tiny file (~hundreds of bytes) that
 *      lists every CVE created or modified in the most recent ~7-min
 *      window. MITRE refreshes this file continuously.
 *
 *   2. For each `new` + `updated` entry, fetch the individual CVE JSON
 *      from the `githubLink` (raw.githubusercontent.com — no auth, no
 *      rate-limit issues for our cadence).
 *
 *   3. Map the CVE List V5 shape to our `vulnerabilities` schema and
 *      upsert. CVSS is *optional* in CVE.org records (often absent
 *      until NVD analyses) — leave it null when missing so the
 *      work-driven enrichment trigger (migration 0033) fires the
 *      OSV→NVD CVSS scoring path automatically.
 *
 * Run at "every 15 minutes" from the scheduler. (Cron pattern in the
 * scheduler entry — not inlined here to avoid closing this JSDoc block.)
 */

import { db, sql } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import { indexSingleVulnerability } from '../opensearch';
import type { OTXSyncOptions, SyncResult } from './types';

const log = createLogger('FeedSync:cveorg');

const DELTA_URL = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json';
const FETCH_TIMEOUT_MS = 10_000;
const FETCH_CONCURRENCY = 8;
const BATCH_SIZE = 100;

// ---------------------------------------------------------------------------
// CVE List V5 schema (subset we care about)
// ---------------------------------------------------------------------------

interface DeltaEntry {
    cveId: string;
    cveOrgLink?: string;
    githubLink: string;
    dateUpdated?: string;
}

interface DeltaResponse {
    fetchTime: string;
    numberOfChanges: number;
    new: DeltaEntry[];
    updated: DeltaEntry[];
}

interface CveDescription { lang: string; value: string }

interface CveAffected {
    vendor?: string;
    product?: string;
    versions?: Array<{ version?: string; status?: string }>;
}

interface CveMetric {
    cvssV4_0?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
    cvssV3_1?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
    cvssV3_0?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
}

interface CveProblemDescription { cweId?: string; description?: string; lang?: string; type?: string }
interface CveProblemType { descriptions?: CveProblemDescription[] }

interface CveReference { url: string; tags?: string[] }

interface CveRecord {
    dataType?: string;
    cveMetadata: {
        cveId: string;
        state?: string;
        datePublished?: string;
        dateUpdated?: string;
    };
    containers?: {
        cna?: {
            descriptions?: CveDescription[];
            affected?: CveAffected[];
            metrics?: CveMetric[];
            problemTypes?: CveProblemType[];
            references?: CveReference[];
        };
    };
}

// ---------------------------------------------------------------------------
// Sync entrypoint
// ---------------------------------------------------------------------------

export async function syncCveOrgFeed(_options: OTXSyncOptions = {}): Promise<SyncResult> {
    const result: SyncResult = {
        success: true,
        pulsesProcessed: 0,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors: [],
    };

    let delta: DeltaResponse;
    try {
        delta = await fetchJson<DeltaResponse>(DELTA_URL);
    } catch (err) {
        result.success = false;
        result.errors.push(`Failed to fetch CVE.org delta: ${(err as Error).message}`);
        log.error('Delta fetch failed', err as Error);
        return result;
    }

    const entries: DeltaEntry[] = [...(delta.new ?? []), ...(delta.updated ?? [])];
    result.indicatorsProcessed = entries.length;
    result.pulsesProcessed = 1;

    if (entries.length === 0) {
        log.info('CVE.org delta empty', { fetchTime: delta.fetchTime });
        return result;
    }

    log.info('CVE.org delta', {
        fetchTime: delta.fetchTime,
        new: delta.new?.length ?? 0,
        updated: delta.updated?.length ?? 0,
    });

    // Fan-out fetch with a concurrency cap (be polite to GitHub raw).
    type VulnRow = NonNullable<ReturnType<typeof toRow>>;
    const records: VulnRow[] = [];
    for (let i = 0; i < entries.length; i += FETCH_CONCURRENCY) {
        const chunk = entries.slice(i, i + FETCH_CONCURRENCY);
        const settled = await Promise.allSettled(
            chunk.map(async (e) => {
                const record = await fetchJson<CveRecord>(e.githubLink);
                return toRow(record);
            }),
        );
        for (const s of settled) {
            if (s.status === 'fulfilled' && s.value) {
                records.push(s.value);
            } else if (s.status === 'rejected') {
                result.errors.push(`Fetch failed: ${(s.reason as Error)?.message ?? 'unknown'}`);
            }
        }
    }

    if (records.length === 0) {
        log.warn('No parsable CVE records from delta');
        return result;
    }

    // Upsert. The PG trigger fires NOTIFY rinjani_work for any row with
    // NULL cvss_score — `workListener` then queues OSV+NVD enrichment.
    // We also call indexSingleVulnerability directly below — the trigger-
    // based `opensearch_sync` notification drops messages whenever the
    // API process restarts mid-write, so relying on it alone leaves
    // CVEs in Postgres but invisible to /vulnerabilities.
    const upsertedRows: Array<{ id: string; cveId: string }> = [];
    for (let i = 0; i < records.length; i += BATCH_SIZE) {
        const batch = records.slice(i, i + BATCH_SIZE);
        try {
            const returned = await db.insert(vulnerabilities).values(batch)
                .onConflictDoUpdate({
                    target: vulnerabilities.cveId,
                    set: {
                        // CVE.org descriptions are authoritative — prefer
                        // ours-if-set-and-non-empty, otherwise take theirs.
                        description: sql`COALESCE(NULLIF(${vulnerabilities.description}, ''), EXCLUDED.description)`,
                        cweId: sql`COALESCE(EXCLUDED.cwe_id, ${vulnerabilities.cweId})`,
                        references: sql`COALESCE(EXCLUDED.references, ${vulnerabilities.references})`,
                        // CVSS: only overwrite if CVE.org has one AND we don't.
                        // Most CVE.org records have no CVSS — leave existing
                        // (OSV/NVD-derived) scores alone.
                        cvssScore: sql`COALESCE(${vulnerabilities.cvssScore}, EXCLUDED.cvss_score)`,
                        cvssVector: sql`COALESCE(${vulnerabilities.cvssVector}, EXCLUDED.cvss_vector)`,
                        severity: sql`COALESCE(${vulnerabilities.severity}, EXCLUDED.severity)`,
                        // Vendor/product can change as CNAs revise records.
                        vendorProject: sql`COALESCE(EXCLUDED.vendor_project, ${vulnerabilities.vendorProject})`,
                        product: sql`COALESCE(EXCLUDED.product, ${vulnerabilities.product})`,
                        publishedDate: sql`COALESCE(EXCLUDED.published_date, ${vulnerabilities.publishedDate})`,
                        // Always take CVE.org's lastModified — they're the source of truth.
                        lastModified: sql`EXCLUDED.last_modified`,
                        rawData: sql`EXCLUDED.raw_data`,
                        updatedAt: new Date(),
                    },
                })
                .returning({ id: vulnerabilities.id, cveId: vulnerabilities.cveId });
            upsertedRows.push(...returned);
            result.indicatorsAdded += returned.length;
        } catch (err) {
            log.error('Batch upsert failed', err as Error);
            result.errors.push(`Upsert failed: ${(err as Error).message}`);
        }
    }

    // Index to OpenSearch directly — don't depend on the LISTEN/NOTIFY
    // path because dropped notifications during API restarts have already
    // bitten us. Fetch the full rows back and feed the existing indexer.
    if (upsertedRows.length > 0) {
        try {
            const rows = await db.select().from(vulnerabilities)
                .where(sql`${vulnerabilities.id} IN ${upsertedRows.map(r => r.id)}`);
            let indexed = 0;
            for (const row of rows) {
                try {
                    await indexSingleVulnerability(row as Record<string, unknown>);
                    indexed++;
                } catch (err) {
                    log.warn('OpenSearch index failed for vuln', {
                        cveId: (row as { cveId?: string }).cveId,
                        error: (err as Error).message,
                    });
                }
            }
            log.info('CVE.org → OpenSearch index complete', { indexed, total: rows.length });
        } catch (err) {
            log.error('OpenSearch bulk index step failed', err as Error);
            result.errors.push(`OS index failed: ${(err as Error).message}`);
        }
    }

    log.info('CVE.org sync complete', {
        fetched: entries.length,
        upserted: records.length,
        errors: result.errors.length,
    });

    return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(url: string): Promise<T> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
        const res = await fetch(url, {
            signal: ctrl.signal,
            headers: { 'Accept': 'application/json', 'User-Agent': 'rinjani-cti/1.0' },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
        return await res.json() as T;
    } finally {
        clearTimeout(t);
    }
}

function pickEnglish(descs?: CveDescription[]): string {
    if (!descs?.length) return '';
    return (descs.find(d => d.lang === 'en' || d.lang === 'en-US')?.value
        ?? descs[0].value
        ?? '').slice(0, 2000);
}

function extractCvss(metrics?: CveMetric[]): {
    score: string | null; vector: string | null; severity: string | null;
} {
    if (!metrics?.length) return { score: null, vector: null, severity: null };
    // CVE.org records can carry multiple CVSS metrics from different
    // sources. Prefer the highest spec version (v4 > v3.1 > v3.0) — same
    // policy as `nvdSync.extractCVSS`.
    for (const m of metrics) {
        const v = m.cvssV4_0 ?? m.cvssV3_1 ?? m.cvssV3_0;
        if (v?.baseScore != null) {
            return {
                score: v.baseScore.toString(),
                vector: v.vectorString ?? null,
                severity: v.baseSeverity?.toLowerCase() ?? null,
            };
        }
    }
    return { score: null, vector: null, severity: null };
}

function extractCwe(problemTypes?: CveProblemType[]): string | null {
    if (!problemTypes?.length) return null;
    for (const pt of problemTypes) {
        for (const d of pt.descriptions ?? []) {
            if (d.cweId?.startsWith('CWE-')) return d.cweId;
        }
    }
    return null;
}

function toRow(rec: CveRecord) {
    const meta = rec.cveMetadata;
    if (!meta?.cveId) return null;

    // Skip RESERVED / REJECTED records — they have no real content.
    if (meta.state && meta.state !== 'PUBLISHED') return null;

    const cna = rec.containers?.cna;
    const description = pickEnglish(cna?.descriptions);
    const affected = cna?.affected?.[0];
    const cvss = extractCvss(cna?.metrics);
    const cwe = extractCwe(cna?.problemTypes);
    const refs = (cna?.references ?? []).map(r => r.url).filter(Boolean).slice(0, 20);

    return {
        cveId: meta.cveId,
        description,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        severity: cvss.severity,
        cweId: cwe,
        isExploited: false,
        vendorProject: affected?.vendor ?? null,
        product: affected?.product ?? null,
        references: refs,
        publishedDate: meta.datePublished ? new Date(meta.datePublished) : null,
        lastModified: meta.dateUpdated ? new Date(meta.dateUpdated) : new Date(),
        rawData: { source: 'cve.org', state: meta.state ?? 'PUBLISHED' },
    };
}
