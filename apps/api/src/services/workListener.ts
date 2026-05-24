/**
 * Work-driven enrichment dispatcher.
 *
 * Listens on the Postgres NOTIFY channel `rinjani_work` and translates
 * notifications into BullMQ jobs. The triggers fire whenever data
 * appears that needs enrichment — e.g. a CISA KEV row with no CVSS.
 *
 * Dedup: many INSERTs in a bulk feed sync produce many NOTIFYs of the
 * same kind. We use a short Redis TTL (`SET NX EX`) to coalesce them
 * into a single enqueue per kind every DEDUP_WINDOW_SECONDS. The
 * enrichment workers already drain their backlogs themselves, so one
 * wake-up per window is sufficient.
 *
 * Pattern mirrored from db-listener.ts (the OpenSearch sync listener).
 * Reconnects on connection drop with capped backoff.
 */

import pg from 'pg';
import { cveEnrichmentQueue, enrichmentQueue } from '../queues';
import { db, sql } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { cacheConnection } from './redis';
import { createLogger } from '../lib/logger';

const log = createLogger('WorkListener');
const { Client } = pg;

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/rinjani_v3';
const RECONNECT_DELAY_MS = 5000;
const MAX_RECONNECT_ATTEMPTS = 10;
const CHANNEL = 'rinjani_work';

/**
 * Window for collapsing repeated NOTIFYs of the same kind. Sized to
 * absorb a bulk feed-sync's worth of inserts without queueing 1000
 * enrichment jobs — one is enough because the worker drains the backlog.
 */
const DEDUP_WINDOW_SECONDS = 30;

/**
 * Max IOCs enqueued per sweep wake-up. Caps the per-window cost against
 * external enrichment APIs (VirusTotal, AbuseIPDB) which charge or rate-limit
 * per call. The next NOTIFY in DEDUP_WINDOW_SECONDS picks up where we left off.
 */
const SWEEP_BATCH_LIMIT = 100;

let client: pg.Client | null = null;
let isListening = false;
let reconnectAttempts = 0;

interface WorkStats {
    notifications: number;
    enqueued: number;
    dedupSkipped: number;
    errors: number;
    lastNotificationAt: Date | null;
}
const stats: WorkStats = {
    notifications: 0,
    enqueued: 0,
    dedupSkipped: 0,
    errors: 0,
    lastNotificationAt: null,
};

// ============================================================================
// Dispatch
// ============================================================================

/**
 * SET NX EX — returns "OK" if the key was new (we should dispatch),
 * null if the key existed (recent duplicate, skip).
 */
async function shouldDispatch(kind: string): Promise<boolean> {
    const key = `work-dedup:${kind}`;
    const result = await cacheConnection.set(key, '1', 'EX', DEDUP_WINDOW_SECONDS, 'NX');
    return result === 'OK';
}

async function handleNotification(payload: string) {
    stats.notifications++;
    stats.lastNotificationAt = new Date();

    // Payload is the work kind string ("cve-enrich", future "actor-enrich", …).
    const kind = payload.trim();

    try {
        if (!(await shouldDispatch(kind))) {
            stats.dedupSkipped++;
            return;
        }

        switch (kind) {
            case 'cve-enrich':
                await cveEnrichmentQueue.add('work-driven', {
                    type: 'all',
                    batchSize: 50,
                }, {
                    // Best-effort: dedup at the queue layer as well so any
                    // races in the Redis dedup don't create duplicates.
                    jobId: `work-driven-cve-enrich-${Math.floor(Date.now() / (DEDUP_WINDOW_SECONDS * 1000))}`,
                });
                stats.enqueued++;
                log.info('Enqueued enrichment job', { kind });
                break;

            case 'ioc-enrich': {
                // IOC enrichment is per-row (external APIs charge per call).
                // Query for un-enriched rows and enqueue individual jobs.
                const queued = await sweepIocsBacklog(SWEEP_BATCH_LIMIT);
                stats.enqueued += queued;
                log.info('IOC sweep enqueued', { kind, queued });
                break;
            }

            default:
                log.warn('Unknown work kind, ignoring', { kind });
        }
    } catch (err) {
        stats.errors++;
        log.error('Failed to dispatch work notification', err as Error, { kind });
    }
}

// ============================================================================
// LISTEN lifecycle (mirrored from db-listener.ts)
// ============================================================================

export async function startWorkListener(): Promise<void> {
    if (isListening) {
        log.info('Already listening');
        return;
    }

    try {
        client = new Client({ connectionString: DATABASE_URL });

        client.on('notification', (msg: pg.Notification) => {
            if (msg.channel === CHANNEL && msg.payload) {
                void handleNotification(msg.payload);
            }
        });

        client.on('error', (err: Error) => {
            log.error('Connection error', new Error(err.message));
            isListening = false;
            scheduleReconnect();
        });

        client.on('end', () => {
            log.info('Connection closed');
            isListening = false;
        });

        await client.connect();
        await client.query(`LISTEN ${CHANNEL}`);

        isListening = true;
        reconnectAttempts = 0;
        log.info('Listening for work notifications', { channel: CHANNEL });
    } catch (err) {
        log.error('Failed to start work listener', err as Error);
        scheduleReconnect();
    }
}

function scheduleReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        log.error('Max reconnection attempts reached for work listener');
        return;
    }
    reconnectAttempts++;
    const delay = RECONNECT_DELAY_MS * Math.min(reconnectAttempts, 6);
    log.info('Reconnecting work listener', {
        delaySec: delay / 1000,
        attempt: reconnectAttempts,
        maxAttempts: MAX_RECONNECT_ATTEMPTS,
    });
    setTimeout(() => { void startWorkListener(); }, delay);
}

export async function stopWorkListener(): Promise<void> {
    if (client) {
        try {
            await client.query(`UNLISTEN ${CHANNEL}`);
            await client.end();
        } catch {
            // Ignore errors on shutdown
        }
        client = null;
        isListening = false;
        log.info('Work listener stopped');
    }
}

export function getWorkListenerStats() {
    return { isListening, reconnectAttempts, ...stats };
}

/**
 * Find un-enriched IOCs and enqueue per-row enrichment jobs.
 *
 * Uses `enriched_at IS NULL` as the "needs enrichment" signal — set by
 * the IOC enrichment worker on successful enrichment, so this is naturally
 * idempotent (already-enriched rows aren't re-touched). Skips IOCs older
 * than 30 days to avoid unbounded backlog growth from historical data.
 */
export async function sweepIocsBacklog(limit = SWEEP_BATCH_LIMIT): Promise<number> {
    const rows = await db
        .select({ id: iocs.id, value: iocs.value, type: iocs.type })
        .from(iocs)
        .where(sql`${iocs.enrichedAt} IS NULL AND ${iocs.createdAt} > NOW() - INTERVAL '30 days'`)
        .limit(limit);

    if (rows.length === 0) return 0;

    let enqueued = 0;
    for (const row of rows) {
        try {
            await enrichmentQueue.add(`work-driven-${row.id}`, {
                iocId: row.id,
                iocValue: row.value,
                iocType: row.type,
                // Use the worker's default source list — sources optional.
            }, {
                // jobId dedups within the queue if the same IOC re-NOTIFYs
                // within a short window (e.g. multiple UPDATEs in a feed sync).
                jobId: `ioc-enrich-${row.id}`,
            });
            enqueued++;
        } catch (err) {
            log.warn('Failed to enqueue IOC enrichment', { iocId: row.id, error: (err as Error).message });
        }
    }
    return enqueued;
}

/**
 * One-shot backstop sweep: enqueue enrichment work immediately, regardless
 * of NOTIFY state. Called at worker boot to catch anything that arrived
 * while the listener was offline, and exposed to admin "Run sweep" buttons.
 *
 * - `cve-enrich`  → enqueues a single backlog-drain job (worker batches DB itself)
 * - `ioc-enrich`  → enqueues per-IOC jobs (worker is per-row)
 */
export async function triggerEnrichmentSweep(
    kind: 'cve-enrich' | 'ioc-enrich' = 'cve-enrich',
): Promise<{ jobId?: string; enqueued?: number }> {
    switch (kind) {
        case 'cve-enrich': {
            // 50 keeps the job under the worker's lock-renew window even
            // when CVE_API_KEY isn't set (worst case ~5min for 50 CVEs).
            // The worker still drains the full backlog over multiple
            // wake-ups — one chunk per NOTIFY-dedup window.
            const job = await cveEnrichmentQueue.add('sweep', { type: 'all', batchSize: 50 });
            log.info('Triggered CVE enrichment sweep', { kind, jobId: job.id });
            return { jobId: String(job.id) };
        }
        case 'ioc-enrich': {
            const enqueued = await sweepIocsBacklog(SWEEP_BATCH_LIMIT);
            log.info('Triggered IOC enrichment sweep', { kind, enqueued });
            return { enqueued };
        }
        default:
            throw new Error(`Unknown sweep kind: ${kind}`);
    }
}
