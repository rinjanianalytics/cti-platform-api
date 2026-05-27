/**
 * CVE Enrichment Worker
 *
 * Enriches vulnerabilities that are missing data:
 * 1. CVSS scores — for CISA KEV entries that arrived without them
 * 2. Published dates — for CVEs missing publishedDate
 *
 * Designed to run as a scheduled BullMQ job (daily) or triggered
 * after CISA sync completes.
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { and, db, eq, isNull } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import { fetchFromOsv, type CveEnrichmentData } from '../../services/osvClient';

export interface CVEEnrichmentJobData {
    type: 'cvss' | 'dates' | 'all';
    batchSize?: number;
}

// Accept either name — NVD_API_KEY matches NIST's docs, CVE_API_KEY is the
// legacy codebase name. NVD_API_KEY wins if both are set.
const NVD_API_KEY = process.env.NVD_API_KEY || process.env.CVE_API_KEY || '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RATE_LIMIT_MS = NVD_API_KEY ? 700 : 6500;

// ============================================================================
// NVD API Helpers
// ============================================================================

interface NVDMetrics {
    cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV2?: Array<{ cvssData: { baseScore: number; vectorString: string } }>;
}

/**
 * NVD-only fetch — used as fallback when OSV doesn't have the CVE.
 *
 * NVD covers everything (including proprietary vendors OSV doesn't
 * index) but is rate-limited: ~5 req/30s without an API key, ~50 req/30s
 * with one. Cloudflare gates the API-key signup, so this is the slow
 * path. OSV (no rate limit, no auth) is the primary path.
 *
 * Per-call throttle is enforced inside this function via the module-
 * level `nextNvdCallAt` watermark. Sleeping here (rather than in the
 * worker loop) means OSV calls aren't artificially slowed down — a
 * sweep that finds every CVE in OSV finishes at OSV's full speed.
 */
let nextNvdCallAt = 0;

async function fetchFromNvd(cveId: string): Promise<CveEnrichmentData | null> {
    const now = Date.now();
    if (now < nextNvdCallAt) {
        await new Promise(r => setTimeout(r, nextNvdCallAt - now));
    }
    nextNvdCallAt = Date.now() + RATE_LIMIT_MS;

    try {
        const url = new URL(NVD_BASE_URL);
        url.searchParams.append('cveId', cveId);

        const response = await fetch(url.toString(), {
            headers: NVD_API_KEY ? { apiKey: NVD_API_KEY } : {},
        });

        if (!response.ok) return null;

        const data = await response.json() as { vulnerabilities?: Array<{ cve: { metrics?: NVDMetrics; published?: string; lastModified?: string } }> };
        if (!data.vulnerabilities || data.vulnerabilities.length === 0) return null;

        const cve = data.vulnerabilities[0].cve;
        const metrics: NVDMetrics = cve.metrics || {};

        // Extract CVSS — prefer v3.1 > v3.0 > v2
        let cvss: CveEnrichmentData['cvss'] | undefined;
        if (metrics.cvssMetricV31?.[0]) {
            const d = metrics.cvssMetricV31[0].cvssData;
            cvss = { score: d.baseScore, severity: d.baseSeverity.toLowerCase(), vector: d.vectorString };
        } else if (metrics.cvssMetricV30?.[0]) {
            const d = metrics.cvssMetricV30[0].cvssData;
            cvss = { score: d.baseScore, severity: d.baseSeverity.toLowerCase(), vector: d.vectorString };
        } else if (metrics.cvssMetricV2?.[0]) {
            const d = metrics.cvssMetricV2[0].cvssData;
            const score = d.baseScore;
            const severity = score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
            cvss = { score, severity, vector: d.vectorString };
        }

        return {
            cvss,
            published: cve.published ? new Date(cve.published) : undefined,
            lastModified: cve.lastModified ? new Date(cve.lastModified) : undefined,
            source: 'nvd',
        };
    } catch {
        return null;
    }
}

/**
 * Multi-source CVE lookup: OSV first (no auth, no rate limit), NVD if
 * OSV doesn't know the CVE or didn't return a numeric CVSS score.
 *
 * Returns null only if both sources fail.
 */
async function fetchCVEData(cveId: string): Promise<CveEnrichmentData | null> {
    const osv = await fetchFromOsv(cveId);
    // OSV has the CVE *and* gave us a numeric CVSS → use it directly.
    if (osv?.cvss) return osv;

    // OSV didn't have it (or only had v2 / no severity) — fall back to NVD.
    const nvd = await fetchFromNvd(cveId);
    if (nvd?.cvss) return nvd;

    // Last resort: return whatever metadata either source gave us so
    // dates can still be populated even without a score.
    return osv ?? nvd ?? null;
}

// ============================================================================
// Enrichment Functions
// ============================================================================

async function enrichCVSS(log: ReturnType<typeof createLogger>, batchSize: number): Promise<number> {
    // Prioritize exploited CVEs missing CVSS
    const missing = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
    })
        .from(vulnerabilities)
        .where(and(
            eq(vulnerabilities.isExploited, true),
            isNull(vulnerabilities.cvssScore),
        ))
        .limit(batchSize);

    if (missing.length === 0) {
        // Fall back to any CVE missing CVSS
        const anyMissing = await db.select({
            id: vulnerabilities.id,
            cveId: vulnerabilities.cveId,
        })
            .from(vulnerabilities)
            .where(isNull(vulnerabilities.cvssScore))
            .limit(batchSize);

        if (anyMissing.length === 0) {
            log.info('No CVEs missing CVSS scores');
            return 0;
        }
        missing.push(...anyMissing);
    }

    log.info('Enriching CVSS scores', { count: missing.length });
    let enriched = 0;

    for (const vuln of missing) {
        const data = await fetchCVEData(vuln.cveId);
        if (data?.cvss) {
            await db.update(vulnerabilities)
                .set({
                    cvssScore: data.cvss.score.toString(),
                    severity: data.cvss.severity,
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.id, vuln.id));
            enriched++;
            log.debug('CVSS enriched', { cveId: vuln.cveId, score: data.cvss.score });
        }
        // Throttling is now enforced inside fetchFromNvd() — only NVD
        // calls wait, OSV calls run at full speed.
    }

    return enriched;
}

async function enrichDates(log: ReturnType<typeof createLogger>, batchSize: number): Promise<number> {
    const missing = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
    })
        .from(vulnerabilities)
        .where(isNull(vulnerabilities.publishedDate))
        .limit(batchSize);

    if (missing.length === 0) {
        log.info('No CVEs missing published dates');
        return 0;
    }

    log.info('Enriching published dates', { count: missing.length });
    let enriched = 0;

    for (const vuln of missing) {
        const data = await fetchCVEData(vuln.cveId);
        if (data?.published) {
            await db.update(vulnerabilities)
                .set({
                    publishedDate: data.published,
                    lastModified: data.lastModified || new Date(),
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.id, vuln.id));
            enriched++;
            log.debug('Date enriched', { cveId: vuln.cveId });
        }
        // Throttling is now enforced inside fetchFromNvd() — only NVD
        // calls wait, OSV calls run at full speed.
    }

    return enriched;
}

// ============================================================================
// BullMQ Worker
// ============================================================================

export const cveEnrichmentWorker = new Worker<CVEEnrichmentJobData>(
    'cve-enrichment',
    async (job: Job<CVEEnrichmentJobData>) => {
        const log = createLogger('CVE:Enrich');
        const { type = 'all', batchSize = 50 } = job.data;
        log.info('Processing job', { jobId: job.id, type, batchSize });

        try {
            await job.updateProgress(5);
            let cvssEnriched = 0;
            let datesEnriched = 0;

            if (type === 'cvss' || type === 'all') {
                cvssEnriched = await enrichCVSS(log, batchSize);
                await job.updateProgress(50);
            }

            if (type === 'dates' || type === 'all') {
                datesEnriched = await enrichDates(log, batchSize);
                await job.updateProgress(90);
            }

            await job.updateProgress(100);

            log.info('CVE enrichment complete', { cvssEnriched, datesEnriched });
            return {
                success: true,
                type,
                cvssEnriched,
                datesEnriched,
                completedAt: new Date().toISOString(),
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    },
    {
        connection,
        concurrency: 1, // One enrichment at a time — NVD rate limits per IP
        // CVE enrichment is long-running by design (NVD allows ~700ms/call
        // *with* an API key; ~6500ms/call without). A batch of 50 takes
        // 35s–5min depending on whether `CVE_API_KEY` is set, so the
        // default 30s lockDuration trips "job stalled" routinely.
        //
        // 10 minutes covers worst-case (no API key + full batch); the lock
        // is renewed every 5 minutes as long as the event loop is
        // responsive. maxStalledCount: 3 means a worker restart mid-job
        // doesn't permanently fail the job — it'll be retried.
        lockDuration: 10 * 60 * 1000,       // 10 minutes
        lockRenewTime: 5 * 60 * 1000,       // 5 minutes (must be < lockDuration)
        maxStalledCount: 3,                 // retry stalled jobs 3 times before final fail
    }
);
