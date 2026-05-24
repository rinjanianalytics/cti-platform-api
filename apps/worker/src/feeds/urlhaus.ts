/**
 * URLhaus Sync Worker
 * 
 * Fetches malicious URLs from Abuse.ch URLhaus database.
 * https://urlhaus.abuse.ch/
 * 
 * URLhaus provides:
 * - Malicious URLs used for malware distribution
 * - Associated payloads and file hashes
 * - Threat classifications
 * - Online/offline status
 */

import { db } from '@rinjani/db';
import { iocs, syncLogs } from '@rinjani/db/schema';
import { fetchWithRetry } from './_fetch.js';

// =============================================================================
// Configuration
// =============================================================================

const URLHAUS_API_URL = 'https://urlhaus-api.abuse.ch/v1/';
const URLHAUS_AUTH_KEY = process.env.URLHAUS_AUTH_KEY || process.env.THREATFOX_AUTH_KEY || '';
const SYNC_LIMIT = 1000; // Fetch last 1000 URLs
const BATCH_SIZE = 100; // Batch insert size

// Threat type mapping
const THREAT_TYPE_MAP: Record<string, string> = {
    'malware_download': 'malware',
    'botnet_cc': 'c2',
    'ransomware_payment_site': 'ransomware',
    'phishing': 'phishing',
};

// =============================================================================
// Types
// =============================================================================

interface URLhausURL {
    id: string;
    urlhaus_reference: string;
    url: string;
    url_status: string;
    host: string;
    date_added: string;
    threat: string;
    blacklists: {
        spamhaus_dbl: string;
        surbl: string;
    };
    reporter: string;
    larted: string;
    tags: string[] | null;
}

interface URLhausResponse {
    query_status: string;
    urls: URLhausURL[] | null;
}

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchRecentURLs(limit: number): Promise<URLhausURL[]> {
    // URLhaus's /v1/urls/recent/ is a GET endpoint (returns 405 on POST since
    // their unified-auth refresh) and the Auth-Key is sent as a header, not
    // a form field. Get a free key at https://auth.abuse.ch/ → Account → API key.
    const url = new URL(`${URLHAUS_API_URL}urls/recent/`);
    url.searchParams.set('limit', String(limit));

    const headers: Record<string, string> = {};
    if (URLHAUS_AUTH_KEY) headers['Auth-Key'] = URLHAUS_AUTH_KEY;

    const response = await fetchWithRetry(url.toString(), {
        method: 'GET',
        headers,
    }, { name: 'URLhaus' });

    const data: URLhausResponse = (await response.json()) as URLhausResponse;

    if (data.query_status !== 'ok' || !data.urls) {
        throw new Error(`URLhaus query failed: ${data.query_status}`);
    }

    return data.urls;
}

// =============================================================================
// Sync Functions
// =============================================================================

export async function syncURLhaus(): Promise<SyncResult> {
    console.log('[URLhaus] Starting sync...');
    console.log(`[URLhaus] API URL: ${URLHAUS_API_URL}`);

    if (!URLHAUS_AUTH_KEY) {
        console.warn('[URLhaus] ⚠️  No Auth-Key configured. Get one free at: https://auth.abuse.ch/');
        console.warn('[URLhaus] Set URLHAUS_AUTH_KEY or THREATFOX_AUTH_KEY in .env to enable sync');
        return { processed: 0, failed: 0, errors: ['No Auth-Key configured'] };
    }

    console.log(`[URLhaus] Fetching last ${SYNC_LIMIT} URLs...`);

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        const urls = await fetchRecentURLs(SYNC_LIMIT);
        console.log(`[URLhaus] Fetched ${urls.length} URLs`);

        // Batch process URLs
        const iocBatch: any[] = [];

        for (const urlData of urls) {
            try {
                const threatType = THREAT_TYPE_MAP[urlData.threat] || 'malware';

                // Determine severity based on status and blacklists
                let severity: string;
                if (urlData.url_status === 'online') {
                    severity = 'high';
                } else if (urlData.url_status === 'offline') {
                    severity = 'medium';
                } else {
                    severity = 'low';
                }

                const iocRecord = {
                    type: 'url',
                    value: urlData.url,
                    source: 'urlhaus',
                    threatType: threatType,
                    confidence: urlData.url_status === 'online' ? 90 : 70,
                    severity: severity,
                    firstSeen: new Date(urlData.date_added),
                    lastSeen: new Date(),
                    tags: [
                        'urlhaus',
                        urlData.threat,
                        ...(urlData.tags || []),
                    ],
                    metadata: {
                        urlhaus_id: urlData.id,
                        urlhaus_reference: urlData.urlhaus_reference,
                        url_status: urlData.url_status,
                        host: urlData.host,
                        threat: urlData.threat,
                        blacklists: urlData.blacklists,
                        reporter: urlData.reporter,
                        larted: urlData.larted,
                    },
                };

                iocBatch.push(iocRecord);

                // Batch insert when batch is full
                if (iocBatch.length >= BATCH_SIZE) {
                    await insertBatch(iocBatch, result);
                    iocBatch.length = 0; // Clear batch
                }
            } catch (iocError) {
                result.failed++;
                const errorMsg = iocError instanceof Error ? iocError.message : String(iocError);
                if (result.errors.length < 10) {
                    result.errors.push(`URL ${urlData.url}: ${errorMsg}`);
                }
            }
        }

        // Insert remaining URLs
        if (iocBatch.length > 0) {
            await insertBatch(iocBatch, result);
        }

    } catch (error) {
        console.error('[URLhaus] Error fetching URLs:', error);
        const errorMsg = error instanceof Error ? error.message : (error as Error).message;
        result.errors.push(`Fetch error: ${errorMsg}`);
    }

    console.log(`[URLhaus] Sync completed: ${result.processed} URLs, ${result.failed} failed`);
    return result;
}

async function insertBatch(batch: any[], result: SyncResult): Promise<void> {
    try {
        console.log(`[URLhaus] Batch inserting ${batch.length} URLs...`);

        await db.insert(iocs)
            .values(batch)
            .onConflictDoUpdate({
                target: iocs.value,
                set: {
                    lastSeen: new Date(),
                    updatedAt: new Date(),
                },
            });

        result.processed += batch.length;
    } catch (batchError) {
        console.error(`[URLhaus] Batch insert error:`, batchError);
        const errorMsg = batchError instanceof Error ? batchError.message : String(batchError);
        result.errors.push(`Batch insert failed: ${errorMsg}`);
        result.failed += batch.length;
    }
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'urlhaus',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runURLhausSync(): Promise<void> {
    const startedAt = new Date();
    console.log('[URLhaus] Starting full sync...');

    try {
        const result = await syncURLhaus();
        await logSync(result, startedAt);
        console.log('[URLhaus] Full sync completed!');
    } catch (error) {
        console.error('[URLhaus] Sync failed:', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runURLhausSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
