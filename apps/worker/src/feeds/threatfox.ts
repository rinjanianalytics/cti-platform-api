/**
 * ThreatFox Sync Worker
 * 
 * Fetches IOCs from Abuse.ch ThreatFox database.
 * https://threatfox.abuse.ch/
 * 
 * ThreatFox provides:
 * - Malicious IPs, domains, URLs
 * - File hashes (MD5, SHA1, SHA256)
 * - Associated malware families
 * - Threat types and confidence scores
 */

import { db } from '@rinjani/db';
import { iocs, syncLogs } from '@rinjani/db/schema';
import { eq } from '@rinjani/db';
import { daysSinceLastSync } from './delta-sync.js';
import { fetchWithRetry } from './_fetch.js';

// =============================================================================
// Configuration
// =============================================================================

const THREATFOX_API_URL = 'https://threatfox-api.abuse.ch/api/v1/';
const THREATFOX_AUTH_KEY = process.env.THREATFOX_AUTH_KEY || '';
const SYNC_DAYS = 7; // Fetch IOCs from last 7 days
const BATCH_SIZE = 100; // Batch insert size

// IOC type mapping
const IOC_TYPE_MAP: Record<string, string> = {
    'ip:port': 'ip',
    'domain': 'domain',
    'url': 'url',
    'md5_hash': 'hash',
    'sha1_hash': 'hash',
    'sha256_hash': 'hash',
};

// Threat type mapping
const THREAT_TYPE_MAP: Record<string, string> = {
    'botnet_cc': 'c2',
    'payload_delivery': 'malware',
    'ransomware_payment_site': 'ransomware',
    'phishing': 'phishing',
};

// =============================================================================
// Types
// =============================================================================

interface ThreatFoxIOC {
    id: string;
    ioc: string;
    threat_type: string;
    threat_type_desc: string;
    ioc_type: string;
    ioc_type_desc: string;
    malware: string;
    malware_printable: string;
    malware_alias: string | null;
    malware_malpedia: string | null;
    confidence_level: number;
    first_seen: string;
    last_seen: string | null;
    reference: string | null;
    reporter: string;
    tags: string[] | null;
}

interface ThreatFoxResponse {
    query_status: string;
    data: ThreatFoxIOC[] | null;
}

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchRecentIOCs(days: number): Promise<ThreatFoxIOC[]> {
    const payload = {
        query: 'get_iocs',
        days: days,
    };

    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    // Add Auth-Key if available
    if (THREATFOX_AUTH_KEY) {
        headers['Auth-Key'] = THREATFOX_AUTH_KEY;
    }

    const response = await fetchWithRetry(THREATFOX_API_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
    }, { name: 'ThreatFox' });

    const data: ThreatFoxResponse = (await response.json()) as ThreatFoxResponse;

    if (data.query_status !== 'ok' || !data.data) {
        throw new Error(`ThreatFox query failed: ${data.query_status}`);
    }

    return data.data;
}

// =============================================================================
// Sync Functions
// =============================================================================

export async function syncThreatFox(): Promise<SyncResult> {
    console.log('[ThreatFox] Starting sync...');
    console.log(`[ThreatFox] API URL: ${THREATFOX_API_URL}`);

    if (!THREATFOX_AUTH_KEY) {
        console.warn('[ThreatFox] ⚠️  No Auth-Key configured. Get one free at: https://auth.abuse.ch/');
        console.warn('[ThreatFox] Set THREATFOX_AUTH_KEY in .env to enable sync');
        return { processed: 0, failed: 0, errors: ['No Auth-Key configured'] };
    }

    // Delta: compute time window based on last successful sync
    const syncDays = await daysSinceLastSync('threatfox', SYNC_DAYS);
    console.log(`[ThreatFox] Fetching IOCs from last ${syncDays} days (default ${SYNC_DAYS})...`);

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        const iocData = await fetchRecentIOCs(syncDays);
        console.log(`[ThreatFox] Fetched ${iocData.length} IOCs`);

        // Batch process IOCs
        const iocBatch: any[] = [];

        for (const tfIoc of iocData) {
            try {
                const iocType = IOC_TYPE_MAP[tfIoc.ioc_type] || 'unknown';
                const threatType = THREAT_TYPE_MAP[tfIoc.threat_type] || 'malware';

                // Determine severity based on confidence
                let severity: string;
                if (tfIoc.confidence_level >= 75) {
                    severity = 'high';
                } else if (tfIoc.confidence_level >= 50) {
                    severity = 'medium';
                } else {
                    severity = 'low';
                }

                const iocRecord = {
                    type: iocType,
                    value: tfIoc.ioc,
                    source: 'threatfox',
                    threatType: threatType,
                    confidence: tfIoc.confidence_level,
                    severity: severity,
                    firstSeen: new Date(tfIoc.first_seen),
                    lastSeen: tfIoc.last_seen ? new Date(tfIoc.last_seen) : new Date(),
                    tags: [
                        'threatfox',
                        tfIoc.malware_printable,
                        ...(tfIoc.tags || []),
                    ],
                    metadata: {
                        threatfox_id: tfIoc.id,
                        malware: tfIoc.malware_printable,
                        malware_alias: tfIoc.malware_alias,
                        malware_malpedia: tfIoc.malware_malpedia,
                        threat_type_desc: tfIoc.threat_type_desc,
                        ioc_type_desc: tfIoc.ioc_type_desc,
                        reference: tfIoc.reference,
                        reporter: tfIoc.reporter,
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
                    result.errors.push(`IOC ${tfIoc.ioc}: ${errorMsg}`);
                }
            }
        }

        // Insert remaining IOCs
        if (iocBatch.length > 0) {
            await insertBatch(iocBatch, result);
        }

    } catch (error) {
        console.error('[ThreatFox] Error fetching IOCs:', error);
        const errorMsg = error instanceof Error ? error.message : (error as Error).message;
        result.errors.push(`Fetch error: ${errorMsg}`);
    }

    console.log(`[ThreatFox] Sync completed: ${result.processed} IOCs, ${result.failed} failed`);
    return result;
}

async function insertBatch(batch: any[], result: SyncResult): Promise<void> {
    try {
        console.log(`[ThreatFox] Batch inserting ${batch.length} IOCs...`);

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
        console.error(`[ThreatFox] Batch insert error:`, batchError);
        const errorMsg = batchError instanceof Error ? batchError.message : String(batchError);
        result.errors.push(`Batch insert failed: ${errorMsg}`);
        result.failed += batch.length;
    }
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'threatfox',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runThreatFoxSync(): Promise<void> {
    const startedAt = new Date();
    console.log('[ThreatFox] Starting full sync...');

    try {
        const result = await syncThreatFox();
        await logSync(result, startedAt);
        console.log('[ThreatFox] Full sync completed!');
    } catch (error) {
        console.error('[ThreatFox] Sync failed:', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runThreatFoxSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
