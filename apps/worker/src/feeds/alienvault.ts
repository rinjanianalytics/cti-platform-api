/**
 * AlienVault OTX Sync Worker - OPTIMIZED
 * 
 * Fetches threat intelligence pulses and IOCs from AlienVault OTX API.
 * Optimizations:
 * - Batch IOC inserts (100 per batch)
 * - Page timeout (5 minutes)
 * - Max page limit (100 pages)
 * - Better error handling and progress logging
 */

import { db } from '@rinjani/db';
import { pulses, iocs, syncLogs } from '@rinjani/db/schema';
import { eq, sql } from '@rinjani/db';
import { getLastSyncTime, toISOParam } from './delta-sync.js';
import { fetchWithRetry } from './_fetch.js';

// =============================================================================
// Configuration
// =============================================================================

const ALIENVAULT_BASE_URL = process.env.ALIENVAULT_BASE_URL || 'https://otx.alienvault.com';
const ALIENVAULT_API_KEY = process.env.ALIENVAULT_API_KEY || '';
const SYNC_LIMIT = 50; // Pulses per page
const MAX_PAGES = 100; // Maximum pages to fetch (prevent infinite loops)
const PAGE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes per page
const BATCH_SIZE = 100; // IOCs to insert per batch

// =============================================================================
// Types
// =============================================================================

interface OTXIndicator {
    indicator: string;
    type: string;
    created: string;
    content: string;
    title: string;
}

interface OTXPulse {
    id: string;
    name: string;
    description: string;
    author_name: string;
    TLP: string;
    tags: string[];
    references: string[];
    adversary: string;
    targeted_countries: string[];
    industries: string[];
    malware_families: string[];
    attack_ids: string[];
    indicator_count: number;
    subscriber_count: number;
    created: string;
    modified: string;
    indicators: OTXIndicator[];
}

interface OTXResponse {
    results: OTXPulse[];
    count: number;
    next: string | null;
    previous: string | null;
}

// =============================================================================
// API Client
// =============================================================================

async function otxRequest<T>(endpoint: string): Promise<T> {
    const response = await fetchWithRetry(`${ALIENVAULT_BASE_URL}${endpoint}`, {
        method: 'GET',
        headers: {
            'X-OTX-API-KEY': ALIENVAULT_API_KEY,
            'Accept': 'application/json',
        },
    }, { name: 'AlienVault' });

    return response.json() as Promise<T>;
}

// =============================================================================
// Sync Functions
// =============================================================================

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

function mapIndicatorType(otxType: string): string {
    const typeMap: Record<string, string> = {
        'IPv4': 'ip',
        'IPv6': 'ip',
        'domain': 'domain',
        'hostname': 'hostname',
        'URL': 'url',
        'FileHash-MD5': 'hash-md5',
        'FileHash-SHA1': 'hash-sha1',
        'FileHash-SHA256': 'hash-sha256',
        'email': 'email',
    };
    return typeMap[otxType] || 'other';
}

/**
 * Infer threat type from pulse metadata (tags, malware families, adversary)
 */
function inferThreatType(pulse: OTXPulse): string {
    const tags = (pulse.tags || []).map(t => t.toLowerCase());
    const malware = (pulse.malware_families || []).map(m => m.toLowerCase());
    const allTerms = [...tags, ...malware, pulse.adversary?.toLowerCase() || ''];

    // Priority-ordered threat type detection
    if (allTerms.some(t => t.includes('ransomware') || t.includes('ransom'))) return 'ransomware';
    if (allTerms.some(t => t.includes('apt') || t.includes('threat actor') || t.includes('nation-state'))) return 'apt';
    if (allTerms.some(t => t.includes('c2') || t.includes('c&c') || t.includes('command and control') || t.includes('beacon'))) return 'c2';
    if (allTerms.some(t => t.includes('phishing') || t.includes('credential harvesting') || t.includes('spear-phishing'))) return 'phishing';
    if (allTerms.some(t => t.includes('botnet') || t.includes('mirai') || t.includes('emotet'))) return 'botnet';
    if (allTerms.some(t => t.includes('trojan') || t.includes('rat') || t.includes('remote access'))) return 'trojan';
    if (allTerms.some(t => t.includes('stealer') || t.includes('infostealer') || t.includes('keylogger') || t.includes('formgrabber'))) return 'stealer';
    if (allTerms.some(t => t.includes('exploit') || t.includes('vulnerability') || t.includes('cve-') || t.includes('0day') || t.includes('zero-day'))) return 'exploit';
    if (allTerms.some(t => t.includes('miner') || t.includes('cryptominer') || t.includes('cryptojacking') || t.includes('coinhive'))) return 'miner';
    if (allTerms.some(t => t.includes('backdoor') || t.includes('webshell') || t.includes('shell'))) return 'backdoor';
    if (allTerms.some(t => t.includes('dropper') || t.includes('downloader') || t.includes('loader'))) return 'dropper';
    if (allTerms.some(t => t.includes('wiper') || t.includes('destructive'))) return 'wiper';
    if (allTerms.some(t => t.includes('worm') || t.includes('self-propagating'))) return 'worm';
    if (allTerms.some(t => t.includes('spyware') || t.includes('surveillance'))) return 'spyware';
    if (allTerms.some(t => t.includes('adware') || t.includes('pup') || t.includes('potentially unwanted'))) return 'adware';
    if (allTerms.some(t => t.includes('scanner') || t.includes('reconnaissance') || t.includes('port scan'))) return 'scanner';
    if (allTerms.some(t => t.includes('brute') || t.includes('password spray') || t.includes('credential stuffing'))) return 'brute_force';
    if (allTerms.some(t => t.includes('ddos') || t.includes('denial of service') || t.includes('amplification'))) return 'ddos';
    if (allTerms.some(t => t.includes('spam') || t.includes('scam') || t.includes('fraud'))) return 'spam';
    if (allTerms.some(t => t.includes('dns') || t.includes('sinkhole') || t.includes('dga'))) return 'dns_abuse';

    // Malware family present but no specific type matched
    if (malware.length > 0) return 'malware';

    // IOC context-based fallback (if indicators are present)
    if (pulse.indicators && pulse.indicators.length > 0) {
        const types = pulse.indicators.map(i => i.type.toLowerCase());
        if (types.some(t => t.includes('url'))) return 'malicious_url';
        if (types.some(t => t.includes('domain') || t.includes('hostname'))) return 'malicious_domain';
        if (types.some(t => t.includes('ip'))) return 'malicious_ip';
        if (types.some(t => t.includes('hash') || t.includes('file'))) return 'malicious_file';
        if (types.some(t => t.includes('email'))) return 'malicious_email';
    }

    return 'unclassified';
}

/**
 * Infer severity from TLP level and adversary information
 */
function inferSeverity(pulse: OTXPulse): string {
    // TLP-based severity
    const tlp = (pulse.TLP || '').toLowerCase();
    if (tlp === 'red') return 'critical';
    if (tlp === 'amber') return 'high';

    // APT or named adversary = high severity
    if (pulse.adversary && pulse.adversary.length > 0) return 'high';

    // Check tags for severity hints
    const tags = (pulse.tags || []).map(t => t.toLowerCase());
    if (tags.some(t => t.includes('critical') || t.includes('ransomware') || t.includes('apt'))) return 'critical';
    if (tags.some(t => t.includes('high') || t.includes('targeted') || t.includes('exploit'))) return 'high';
    if (tags.some(t => t.includes('low') || t.includes('spam'))) return 'low';

    // Default based on TLP
    if (tlp === 'green') return 'medium';

    return 'medium';
}

/**
 * Infer confidence from subscriber count and data quality
 */
function inferConfidence(pulse: OTXPulse): number {
    let confidence = 50; // Base confidence

    // Higher subscriber count = more trusted
    const subscribers = pulse.subscriber_count || 0;
    if (subscribers > 1000) confidence += 25;
    else if (subscribers > 100) confidence += 15;
    else if (subscribers > 10) confidence += 5;

    // Named adversary = higher confidence
    if (pulse.adversary && pulse.adversary.length > 0) confidence += 10;

    // More indicators = more complete
    const indicatorCount = pulse.indicator_count || 0;
    if (indicatorCount > 100) confidence += 5;

    // References increase confidence
    if (pulse.references && pulse.references.length > 0) confidence += 5;

    // MITRE ATT&CK IDs increase confidence
    if (pulse.attack_ids && pulse.attack_ids.length > 0) confidence += 5;

    // Cap at 95 (never 100% from automated inference)
    return Math.min(confidence, 95);
}

async function syncAlienVault(): Promise<SyncResult> {
    console.log('[AlienVault] Starting sync...');
    console.log(`[AlienVault] API URL: ${ALIENVAULT_BASE_URL}`);

    // Delta sync: only fetch pulses modified since last successful sync
    const lastSync = await getLastSyncTime('alienvault_pulses');
    const modifiedSince = lastSync ? toISOParam(lastSync) : null;
    if (modifiedSince) {
        console.log(`[AlienVault] Delta sync — fetching pulses modified since ${modifiedSince}`);
    } else {
        console.log('[AlienVault] First run — full sync');
    }

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    if (!ALIENVAULT_API_KEY) {
        result.errors.push('ALIENVAULT_API_KEY not configured');
        return result;
    }

    let page = 1;
    let hasMore = true;
    let totalIndicators = 0;

    while (hasMore && page <= MAX_PAGES) {
        const pageStartTime = Date.now();

        try {
            console.log(`[AlienVault] Fetching subscribed pulses page ${page}/${MAX_PAGES}...`);

            // Wrap API call with timeout
            let endpoint = `/api/v1/pulses/subscribed?limit=${SYNC_LIMIT}&page=${page}`;
            if (modifiedSince) {
                endpoint += `&modified_since=${modifiedSince}`;
            }
            const fetchPromise = otxRequest<OTXResponse>(endpoint);

            const timeoutPromise = new Promise<never>((_, reject) =>
                setTimeout(() => reject(new Error('Page fetch timeout')), PAGE_TIMEOUT_MS)
            );

            const data = await Promise.race([fetchPromise, timeoutPromise]);

            if (!data.results || data.results.length === 0) {
                console.log(`[AlienVault] No more results at page ${page}`);
                hasMore = false;
                break;
            }

            console.log(`[AlienVault] Processing ${data.results.length} pulses from page ${page}...`);

            // Collect all IOCs for batch insert
            const iocBatch: Array<typeof iocs.$inferInsert> = [];

            for (const pulse of data.results) {
                try {
                    // Upsert pulse
                    const existing = await db.select()
                        .from(pulses)
                        .where(eq(pulses.otxId, pulse.id))
                        .limit(1);

                    const pulseData = {
                        otxId: pulse.id,
                        name: pulse.name,
                        description: pulse.description || null,
                        author: pulse.author_name || null,
                        tlp: pulse.TLP || 'white',
                        tags: pulse.tags || [],
                        adversary: pulse.adversary || null,
                        targetedCountries: pulse.targeted_countries || [],
                        industries: pulse.industries || [],
                        malwareFamilies: pulse.malware_families || [],
                        attackIds: pulse.attack_ids || [],
                        indicatorCount: pulse.indicator_count || 0,
                        subscriberCount: pulse.subscriber_count || 0,
                        otxCreated: pulse.created ? new Date(pulse.created) : null,
                        otxModified: pulse.modified ? new Date(pulse.modified) : null,
                        syncedAt: new Date(),
                    };

                    if (existing.length > 0) {
                        await db.update(pulses)
                            .set({ ...pulseData, updatedAt: new Date() })
                            .where(eq(pulses.otxId, pulse.id));
                    } else {
                        await db.insert(pulses).values(pulseData);
                    }

                    // Collect indicators for batch insert
                    if (pulse.indicators && pulse.indicators.length > 0) {
                        // Infer threat type from pulse data
                        const threatType = inferThreatType(pulse);
                        // Infer severity from TLP and adversary info
                        const severity = inferSeverity(pulse);
                        // Confidence based on subscriber count and adversary info
                        const confidence = inferConfidence(pulse);

                        for (const indicator of pulse.indicators) {
                            iocBatch.push({
                                type: mapIndicatorType(indicator.type),
                                value: indicator.indicator,
                                source: 'alienvault',
                                threatType,
                                severity,
                                confidence,
                                pulseId: pulse.id,
                                tags: pulse.tags || [],
                                firstSeen: indicator.created ? new Date(indicator.created) : null,
                                lastSeen: new Date(),
                            });
                        }
                    }

                    result.processed++;
                } catch (pulseError) {
                    result.failed++;
                    const errorMsg = pulseError instanceof Error ? pulseError.message : String(pulseError);
                    result.errors.push(`Pulse ${pulse.name}: ${errorMsg}`);
                }
            }

            // Batch insert IOCs
            if (iocBatch.length > 0) {
                // Deduplicate by IOC value (keep last occurrence)
                const deduped = new Map<string, typeof iocs.$inferInsert>();
                for (const ioc of iocBatch) {
                    deduped.set(ioc.value, ioc);
                }
                const uniqueIOCs = Array.from(deduped.values());

                console.log(`[AlienVault] Batch inserting ${uniqueIOCs.length} unique IOCs (${iocBatch.length - uniqueIOCs.length} duplicates removed)...`);

                // Insert in chunks to avoid overwhelming the database
                for (let i = 0; i < uniqueIOCs.length; i += BATCH_SIZE) {
                    const chunk = uniqueIOCs.slice(i, i + BATCH_SIZE);
                    try {
                        await db.insert(iocs)
                            .values(chunk)
                            .onConflictDoUpdate({
                                target: iocs.value,
                                set: {
                                    threatType: sql`COALESCE(excluded.threat_type, ${iocs.threatType})`,
                                    severity: sql`COALESCE(excluded.severity, ${iocs.severity})`,
                                    confidence: sql`COALESCE(excluded.confidence, ${iocs.confidence})`,
                                    tags: sql`excluded.tags`,
                                    lastSeen: new Date(),
                                    updatedAt: new Date(),
                                },
                            });
                        totalIndicators += chunk.length;
                    } catch (batchError) {
                        console.error(`[AlienVault] Batch insert error:`, batchError);
                        const errorMsg = batchError instanceof Error ? batchError.message : String(batchError);
                        result.errors.push(`Batch insert failed: ${errorMsg}`);
                    }
                }
            }

            const pageTime = ((Date.now() - pageStartTime) / 1000).toFixed(1);
            console.log(`[AlienVault] Page ${page} completed in ${pageTime}s (${totalIndicators} total IOCs)`);

            hasMore = data.next !== null && page < MAX_PAGES;
            page++;

            // Rate limiting - wait 1 second between pages
            if (hasMore) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }

        } catch (error) {
            const errorMsg = error instanceof Error ? error.message : (error as Error).message;
            console.error(`[AlienVault] Error on page ${page}:`, errorMsg);
            result.errors.push(`Page ${page}: ${errorMsg}`);

            // Stop on timeout or critical errors
            if (errorMsg.includes('timeout') || errorMsg.includes('FATAL')) {
                console.log(`[AlienVault] Stopping sync due to critical error`);
                hasMore = false;
            } else {
                // Skip to next page on non-critical errors
                page++;
                if (page > MAX_PAGES) hasMore = false;
            }
        }
    }

    if (page > MAX_PAGES) {
        console.log(`[AlienVault] Reached max page limit (${MAX_PAGES})`);
    }

    console.log(`[AlienVault] ✅ Synced ${result.processed} pulses, ${totalIndicators} IOCs (${result.failed} failed)`);
    return result;
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    // Status precedence:
    //   no errors AND items processed         → success
    //   errors exist AND items processed      → partial (some pages worked)
    //   errors exist AND nothing processed    → failure (every page bombed)
    //   no errors AND nothing processed       → success (genuinely no new data)
    const hasErrors = result.errors.length > 0;
    const status = hasErrors
        ? (result.processed > 0 ? 'partial' : 'failure')
        : 'success';

    await db.insert(syncLogs).values({
        entityType: 'alienvault_pulses',
        status,
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        lastSyncCursor: new Date().toISOString(),
        errorMessage: hasErrors ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runAlienVaultSync(): Promise<void> {
    const startedAt = new Date();
    console.log('[AlienVault] Starting full sync...');

    try {
        const result = await syncAlienVault();
        await logSync(result, startedAt);
        console.log('[AlienVault] Full sync completed!');
    } catch (error) {
        console.error('[AlienVault] Fatal sync error:', error);
        throw error;
    }
}

// Export for use in feed orchestrator
export { syncAlienVault };
