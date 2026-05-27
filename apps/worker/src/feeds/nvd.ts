/**
 * NVD/CVE Sync Worker
 * 
 * Fetches CVE data from NIST National Vulnerability Database.
 * https://nvd.nist.gov/developers/vulnerabilities
 * 
 * API Key: Configured in .env (CVE_API_KEY)
 * Rate Limit: 5 requests per 30 seconds (with API key)
 * 
 * This complements CISA KEV by providing the full CVE database.
 */

import { db } from '@rinjani/db';
import { vulnerabilities, syncLogs } from '@rinjani/db/schema';
import { sql } from '@rinjani/db';
import { getLastSyncTime, toISOParam } from './delta-sync.js';

// =============================================================================
// Configuration
// =============================================================================

// Accept either name — NVD_API_KEY matches NIST's docs, CVE_API_KEY is the
// legacy codebase name. NVD_API_KEY wins if both are set.
const NVD_API_KEY = process.env.NVD_API_KEY || process.env.CVE_API_KEY || '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RATE_LIMIT_MS = 6000; // 5 requests per 30 seconds = 6 seconds between requests
const RESULTS_PER_PAGE = 2000; // Max allowed by NVD API
const BATCH_SIZE = 100;
const MAX_PAGES = 10; // Limit for initial sync (20K CVEs), remove for full sync

// =============================================================================
// Types
// =============================================================================

interface NVDResponse {
    resultsPerPage: number;
    startIndex: number;
    totalResults: number;
    format: string;
    version: string;
    timestamp: string;
    vulnerabilities: NVDVulnerability[];
}

interface NVDVulnerability {
    cve: {
        id: string;
        sourceIdentifier: string;
        published: string;
        lastModified: string;
        vulnStatus: string;
        descriptions: Array<{
            lang: string;
            value: string;
        }>;
        metrics?: {
            cvssMetricV31?: Array<{
                cvssData: {
                    baseScore: number;
                    baseSeverity: string;
                    vectorString: string;
                };
            }>;
            cvssMetricV30?: Array<{
                cvssData: {
                    baseScore: number;
                    baseSeverity: string;
                    vectorString: string;
                };
            }>;
            cvssMetricV2?: Array<{
                cvssData: {
                    baseScore: number;
                    vectorString: string;
                };
            }>;
        };
        weaknesses?: Array<{
            description: Array<{
                lang: string;
                value: string;
            }>;
        }>;
        references?: Array<{
            url: string;
            source: string;
        }>;
    };
}

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchCVEs(startIndex: number = 0, since?: Date): Promise<NVDResponse> {
    if (!NVD_API_KEY) {
        throw new Error('NVD API key not configured');
    }

    const url = new URL(NVD_BASE_URL);
    url.searchParams.append('startIndex', startIndex.toString());
    url.searchParams.append('resultsPerPage', RESULTS_PER_PAGE.toString());

    // Delta: only fetch CVEs modified since last sync
    if (since) {
        url.searchParams.append('lastModStartDate', since.toISOString());
        url.searchParams.append('lastModEndDate', new Date().toISOString());
    }

    const response = await fetch(url.toString(), {
        headers: {
            'apiKey': NVD_API_KEY,
        },
    });

    if (!response.ok) {
        throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }

    return (await response.json()) as NVDResponse;
}

// Helper to extract CVSS score and severity
function extractCVSS(cve: NVDVulnerability['cve']) {
    const metrics = cve.metrics;

    // Try CVSS v3.1 first (most recent)
    if (metrics?.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
        const cvss = metrics.cvssMetricV31[0].cvssData;
        return {
            score: cvss.baseScore,
            severity: cvss.baseSeverity.toLowerCase(),
            vector: cvss.vectorString,
        };
    }

    // Try CVSS v3.0
    if (metrics?.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
        const cvss = metrics.cvssMetricV30[0].cvssData;
        return {
            score: cvss.baseScore,
            severity: cvss.baseSeverity.toLowerCase(),
            vector: cvss.vectorString,
        };
    }

    // Try CVSS v2
    if (metrics?.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
        const cvss = metrics.cvssMetricV2[0].cvssData;
        const score = cvss.baseScore;
        // Convert CVSS v2 score to severity
        let severity = 'low';
        if (score >= 7.0) severity = 'high';
        else if (score >= 4.0) severity = 'medium';

        return {
            score: score,
            severity: severity,
            vector: cvss.vectorString,
        };
    }

    // No CVSS data available
    return {
        score: 0,
        severity: 'unknown',
        vector: '',
    };
}

// =============================================================================
// Sync Functions
// =============================================================================

export async function syncNVD(): Promise<SyncResult> {
    console.log('[NVD] Starting sync...');
    console.log(`[NVD] API URL: ${NVD_BASE_URL}`);

    if (!NVD_API_KEY) {
        console.warn('[NVD] ⚠️  No API key configured');
        console.warn('[NVD] Set CVE_API_KEY in .env to enable sync');
        return { processed: 0, failed: 0, errors: ['No API key configured'] };
    }

    // Delta sync: only fetch CVEs modified since last successful sync
    const lastSync = await getLastSyncTime('nvd');
    const isDelta = !!lastSync;

    if (isDelta) {
        console.log(`[NVD] Delta sync — fetching CVEs modified since ${toISOParam(lastSync!)}`);
    } else {
        console.log(`[NVD] First run — full sync (max ${MAX_PAGES} pages)`);
    }

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        // Fetch first page
        console.log('[NVD] Fetching initial page...');
        const firstPage = await fetchCVEs(0, lastSync ?? undefined);
        const totalResults = firstPage.totalResults;
        const totalPages = Math.ceil(totalResults / RESULTS_PER_PAGE);

        console.log(`[NVD] Total CVEs matching: ${totalResults.toLocaleString()}`);

        if (totalResults === 0) {
            console.log('[NVD] No new/modified CVEs since last sync');
            return result;
        }

        // Process first page
        await processCVEBatch(firstPage.vulnerabilities, result);

        // For delta sync, fetch ALL pages (result set is small)
        // For full sync, cap at MAX_PAGES
        const pagesToFetch = isDelta ? totalPages : Math.min(totalPages, MAX_PAGES);

        for (let page = 1; page < pagesToFetch; page++) {
            const startIndex = page * RESULTS_PER_PAGE;

            console.log(`[NVD] Fetching page ${page + 1}/${pagesToFetch} (starting at ${startIndex})...`);

            // Rate limiting
            await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS));

            const pageData = await fetchCVEs(startIndex, lastSync ?? undefined);
            await processCVEBatch(pageData.vulnerabilities, result);

            console.log(`[NVD] Progress: ${result.processed.toLocaleString()} CVEs processed`);
        }

    } catch (error) {
        console.error('[NVD] Error:', error);
        const errorMsg = error instanceof Error ? error.message : (error as Error).message;
        result.errors.push(`Sync error: ${errorMsg}`);
    }

    console.log(`[NVD] Sync completed: ${result.processed} CVEs, ${result.failed} failed`);
    return result;
}

async function processCVEBatch(cves: NVDVulnerability[], result: SyncResult): Promise<void> {
    const vulnBatch: any[] = [];

    for (const nvdVuln of cves) {
        try {
            const cve = nvdVuln.cve;

            // Extract description (prefer English)
            const description = cve.descriptions.find(d => d.lang === 'en')?.value ||
                cve.descriptions[0]?.value ||
                'No description available';

            // Extract CVSS data
            const cvss = extractCVSS(cve);

            // Extract CWE weaknesses
            const cwes: string[] = [];
            if (cve.weaknesses) {
                for (const weakness of cve.weaknesses) {
                    for (const desc of weakness.description) {
                        if (desc.value.startsWith('CWE-')) {
                            cwes.push(desc.value);
                        }
                    }
                }
            }

            // Extract references
            const references = cve.references?.map(ref => ref.url) || [];

            const vulnRecord = {
                cveId: cve.id,
                description: description.substring(0, 2000),
                cvssScore: cvss.score > 0 ? cvss.score.toString() : null,
                cvssVector: cvss.vector || null,
                severity: cvss.severity !== 'unknown' ? cvss.severity : null,
                cweId: cwes.length > 0 ? cwes[0] : null,
                isExploited: false, // NVD doesn't track this; CISA KEV does
                vendorProject: cve.sourceIdentifier || null,
                product: null,
                references: references.slice(0, 20),
                publishedDate: new Date(cve.published),
                lastModified: new Date(cve.lastModified),
                rawData: {
                    vulnStatus: cve.vulnStatus,
                    cwes: cwes,
                    source: 'nvd',
                },
            };

            vulnBatch.push(vulnRecord);

            // Batch insert when batch is full
            if (vulnBatch.length >= BATCH_SIZE) {
                await insertBatch(vulnBatch, result);
                vulnBatch.length = 0; // Clear batch
            }
        } catch (cveError) {
            result.failed++;
            const errorMsg = cveError instanceof Error ? cveError.message : String(cveError);
            if (result.errors.length < 10) {
                result.errors.push(`CVE ${nvdVuln.cve.id}: ${errorMsg}`);
            }
        }
    }

    // Insert remaining CVEs
    if (vulnBatch.length > 0) {
        await insertBatch(vulnBatch, result);
    }
}

async function insertBatch(batch: any[], result: SyncResult): Promise<void> {
    try {
        console.log(`[NVD] Batch inserting ${batch.length} CVEs...`);

        await db.insert(vulnerabilities)
            .values(batch)
            .onConflictDoUpdate({
                target: vulnerabilities.cveId,
                set: {
                    // Enrich with CVSS data from NVD (prefer new NVD data)
                    cvssScore: sql`COALESCE(EXCLUDED.cvss_score, ${vulnerabilities.cvssScore})`,
                    cvssVector: sql`COALESCE(EXCLUDED.cvss_vector, ${vulnerabilities.cvssVector})`,
                    // Only update severity if not already set (preserve CISA's assessment)
                    severity: sql`COALESCE(${vulnerabilities.severity}, EXCLUDED.severity)`,
                    // Update description if it was empty
                    description: sql`COALESCE(${vulnerabilities.description}, EXCLUDED.description)`,
                    // Update CWE, references, dates
                    cweId: sql`COALESCE(EXCLUDED.cwe_id, ${vulnerabilities.cweId})`,
                    references: sql`COALESCE(EXCLUDED.references, ${vulnerabilities.references})`,
                    publishedDate: sql`COALESCE(EXCLUDED.published_date, ${vulnerabilities.publishedDate})`,
                    lastModified: sql`EXCLUDED.last_modified`,
                    vendorProject: sql`COALESCE(${vulnerabilities.vendorProject}, EXCLUDED.vendor_project)`,
                    rawData: sql`EXCLUDED.raw_data`,
                    // Preserve CISA KEV data (don't overwrite with NVD defaults)
                    isExploited: sql`COALESCE(${vulnerabilities.isExploited}, EXCLUDED.is_exploited)`,
                    // Always update timestamp
                    updatedAt: new Date(),
                },
            });

        result.processed += batch.length;
    } catch (batchError) {
        console.error(`[NVD] Batch insert error:`, batchError);
        const errorMsg = batchError instanceof Error ? batchError.message : String(batchError);
        result.errors.push(`Batch insert failed: ${errorMsg}`);
        result.failed += batch.length;
    }
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'nvd',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runNVDSync(): Promise<void> {
    const startedAt = new Date();
    console.log('[NVD] Starting full sync...');

    try {
        const result = await syncNVD();
        await logSync(result, startedAt);
        console.log('[NVD] Full sync completed!');
    } catch (error) {
        console.error('[NVD] Sync failed:', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runNVDSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
