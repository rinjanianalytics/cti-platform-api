/**
 * NVD CVE Sync (Recent Changes)
 *
 * Fetches recently modified CVEs from the NIST NVD API.
 * Designed for the BullMQ scheduler (runs hourly) to keep data fresh.
 * The full historical sync is handled by apps/worker/src/feeds/nvd.ts.
 */

import { db, sql } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import type { OTXSyncOptions, SyncResult } from './types';

const log = createLogger('FeedSync:nvd');

const NVD_API_KEY = process.env.CVE_API_KEY || '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 2000;
const RATE_LIMIT_MS = 6000;
const BATCH_SIZE = 200;

interface NVDResponse {
    resultsPerPage: number;
    startIndex: number;
    totalResults: number;
    vulnerabilities: Array<{
        cve: {
            id: string;
            sourceIdentifier: string;
            published: string;
            lastModified: string;
            vulnStatus: string;
            descriptions: Array<{ lang: string; value: string }>;
            metrics?: {
                cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
                cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
                cvssMetricV2?: Array<{ cvssData: { baseScore: number; vectorString: string } }>;
            };
            weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
            references?: Array<{ url: string; source: string }>;
        };
    }>;
}

function extractCVSS(cve: NVDResponse['vulnerabilities'][0]['cve']) {
    const m = cve.metrics;
    if (m?.cvssMetricV31?.[0]) {
        const c = m.cvssMetricV31[0].cvssData;
        return { score: c.baseScore, severity: c.baseSeverity.toLowerCase(), vector: c.vectorString };
    }
    if (m?.cvssMetricV30?.[0]) {
        const c = m.cvssMetricV30[0].cvssData;
        return { score: c.baseScore, severity: c.baseSeverity.toLowerCase(), vector: c.vectorString };
    }
    if (m?.cvssMetricV2?.[0]) {
        const c = m.cvssMetricV2[0].cvssData;
        const score = c.baseScore;
        return { score, severity: score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low', vector: c.vectorString };
    }
    return { score: 0, severity: 'unknown', vector: '' };
}

export async function syncNVDFeed(options: OTXSyncOptions = {}): Promise<SyncResult> {
    const result: SyncResult = {
        success: true,
        pulsesProcessed: 0,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors: [],
    };

    if (!NVD_API_KEY) {
        log.warn('NVD API key not configured (CVE_API_KEY). Skipping NVD sync.');
        result.errors.push('No CVE_API_KEY configured');
        return result;
    }

    try {
        // Fetch CVEs modified in the last 7 days
        const now = new Date();
        const lookbackDays = 7;
        const since = new Date(now.getTime() - lookbackDays * 24 * 60 * 60 * 1000);

        const startDateStr = since.toISOString().replace('Z', '+00:00');
        const endDateStr = now.toISOString().replace('Z', '+00:00');

        log.info('Fetching recently modified CVEs', { since: startDateStr });

        const url = new URL(NVD_BASE_URL);
        url.searchParams.append('lastModStartDate', startDateStr);
        url.searchParams.append('lastModEndDate', endDateStr);
        url.searchParams.append('resultsPerPage', RESULTS_PER_PAGE.toString());

        const response = await fetch(url.toString(), {
            headers: { 'apiKey': NVD_API_KEY },
        });

        if (!response.ok) {
            throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json() as NVDResponse;
        const totalResults = data.totalResults;
        result.pulsesProcessed = 1;
        result.indicatorsProcessed = totalResults;

        log.info('NVD response received', { totalResults, pageSize: data.resultsPerPage });

        // Process first page
        if (data.vulnerabilities?.length > 0) {
            await upsertCVEBatch(data.vulnerabilities, result);
        }

        // Fetch additional pages if needed (max 3 pages for scheduler = 6K CVEs)
        const totalPages = Math.min(Math.ceil(totalResults / RESULTS_PER_PAGE), 3);
        for (let page = 1; page < totalPages; page++) {
            await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS));

            const pageUrl = new URL(NVD_BASE_URL);
            pageUrl.searchParams.append('lastModStartDate', startDateStr);
            pageUrl.searchParams.append('lastModEndDate', endDateStr);
            pageUrl.searchParams.append('resultsPerPage', RESULTS_PER_PAGE.toString());
            pageUrl.searchParams.append('startIndex', (page * RESULTS_PER_PAGE).toString());

            const pageResponse = await fetch(pageUrl.toString(), {
                headers: { 'apiKey': NVD_API_KEY },
            });

            if (!pageResponse.ok) {
                log.warn('NVD page fetch failed', { page, status: pageResponse.status });
                continue;
            }

            const pageData = await pageResponse.json() as NVDResponse;
            if (pageData.vulnerabilities?.length > 0) {
                await upsertCVEBatch(pageData.vulnerabilities, result);
            }
        }

        log.info('NVD sync completed', {
            total: totalResults,
            added: result.indicatorsAdded,
            updated: result.indicatorsUpdated,
        });

    } catch (err) {
        result.success = false;
        result.errors.push(`NVD sync failed: ${(err as Error).message}`);
        log.error('NVD sync failed', err);
    }

    return result;
}

async function upsertCVEBatch(
    cves: NVDResponse['vulnerabilities'],
    result: SyncResult,
): Promise<void> {
    const records = [];

    for (const nvdVuln of cves) {
        const cve = nvdVuln.cve;
        const description = cve.descriptions.find(d => d.lang === 'en')?.value ||
            cve.descriptions[0]?.value || '';
        const cvss = extractCVSS(cve);
        const cwes: string[] = [];
        if (cve.weaknesses) {
            for (const w of cve.weaknesses) {
                for (const d of w.description) {
                    if (d.value.startsWith('CWE-')) cwes.push(d.value);
                }
            }
        }
        const refs = cve.references?.map(r => r.url) || [];

        records.push({
            cveId: cve.id,
            description: description.substring(0, 2000),
            cvssScore: cvss.score > 0 ? cvss.score.toString() : null,
            cvssVector: cvss.vector || null,
            severity: cvss.severity !== 'unknown' ? cvss.severity : null,
            cweId: cwes.length > 0 ? cwes[0] : null,
            isExploited: false,
            vendorProject: cve.sourceIdentifier || null,
            product: null,
            references: refs.slice(0, 20),
            publishedDate: new Date(cve.published),
            lastModified: new Date(cve.lastModified),
            rawData: { vulnStatus: cve.vulnStatus, cwes, source: 'nvd' },
        });
    }

    // Batch insert/upsert
    for (let i = 0; i < records.length; i += BATCH_SIZE) {
        const batch = records.slice(i, i + BATCH_SIZE);
        try {
            await db.insert(vulnerabilities).values(batch)
                .onConflictDoUpdate({
                    target: vulnerabilities.cveId,
                    set: {
                        cvssScore: sql`COALESCE(EXCLUDED.cvss_score, ${vulnerabilities.cvssScore})`,
                        cvssVector: sql`COALESCE(EXCLUDED.cvss_vector, ${vulnerabilities.cvssVector})`,
                        severity: sql`COALESCE(${vulnerabilities.severity}, EXCLUDED.severity)`,
                        description: sql`COALESCE(${vulnerabilities.description}, EXCLUDED.description)`,
                        cweId: sql`COALESCE(EXCLUDED.cwe_id, ${vulnerabilities.cweId})`,
                        references: sql`COALESCE(EXCLUDED.references, ${vulnerabilities.references})`,
                        publishedDate: sql`COALESCE(EXCLUDED.published_date, ${vulnerabilities.publishedDate})`,
                        lastModified: sql`EXCLUDED.last_modified`,
                        vendorProject: sql`COALESCE(${vulnerabilities.vendorProject}, EXCLUDED.vendor_project)`,
                        rawData: sql`EXCLUDED.raw_data`,
                        isExploited: sql`COALESCE(${vulnerabilities.isExploited}, EXCLUDED.is_exploited)`,
                        updatedAt: new Date(),
                    },
                });
            result.indicatorsAdded += batch.length;
        } catch (err) {
            log.error('Batch upsert failed', new Error((err as Error).message));
            result.errors.push(`Batch CVE upsert failed: ${(err as Error).message}`);
        }
    }
}

// `backfillMissingCvss` was removed — the admin /admin/jobs/cvss-backfill
// endpoint now delegates to `triggerEnrichmentSweep('cve-enrich')`, which
// uses the OSV-first multi-source path in `vulnerabilityEnrichment.ts`
// and `osvClient.ts`. The legacy function here was NVD-only and required
// an NVD API key to do anything — strictly inferior to the new path.
