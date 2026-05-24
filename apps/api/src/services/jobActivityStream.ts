/**
 * Job Activity Stream — the data behind the /admin/activity dashboard.
 *
 * Subscribes once at module import to every BullMQ QueueEvents source we
 * care about, normalises events into a single shape, and maintains:
 *
 *   1. A ring buffer of the last RECENT_BUFFER_SIZE events (for the
 *      activity page's initial render).
 *   2. Per-queue rolling counters keyed by event type (for the
 *      throughput cards on the activity page).
 *   3. An EventEmitter that the SSE endpoint subscribes to so live
 *      events stream to the dashboard without polling.
 *
 * The existing `routes/admin/events.ts` SSE endpoint covers a subset of
 * queues and only `completed`/`failed` events. This service covers all
 * 10 queues plus `active` (job started) and `progress` (longer jobs).
 */

import { EventEmitter } from 'node:events';
import {
    feedSyncEvents,
    enrichmentEvents,
    aiAnalysisEvents,
    notificationEvents,
    alertsEvents,
    neo4jSyncEvents,
    cveEnrichmentEvents,
    maintenanceEvents,
} from '../queues/events';
import { createLogger } from '../lib/logger';

const log = createLogger('JobActivityStream');

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type ActivityKind = 'active' | 'completed' | 'failed' | 'progress';

export interface ActivityEvent {
    /** ISO timestamp from the API process. */
    ts: string;
    queue: string;
    jobId: string;
    kind: ActivityKind;
    /** For `completed` — the worker's return value (may be omitted). */
    result?: unknown;
    /** For `failed` — first 240 chars of the error reason. */
    error?: string;
    /** For `progress` — the progress payload (number or object). */
    progress?: unknown;
    /** Monotonic counter (older = smaller). */
    seq: number;
}

export interface ThroughputStats {
    queue: string;
    /** Total events in the buffer (across all kinds). */
    total: number;
    /** Count per event kind. */
    byKind: Record<ActivityKind, number>;
    /** Most recent event timestamp for this queue, ISO. */
    lastAt: string | null;
}

// ---------------------------------------------------------------------------
// Buffer + counters
// ---------------------------------------------------------------------------

const RECENT_BUFFER_SIZE = 200;
const buffer: ActivityEvent[] = [];
let seq = 0;
const emitter = new EventEmitter();

// EventEmitter default is 10 listeners. SSE clients each register one — we
// allow up to 50 concurrent dashboard tabs before warnings fire.
emitter.setMaxListeners(50);

function record(evt: Omit<ActivityEvent, 'ts' | 'seq'>) {
    const enriched: ActivityEvent = {
        ts: new Date().toISOString(),
        seq: ++seq,
        ...evt,
    };
    buffer.push(enriched);
    if (buffer.length > RECENT_BUFFER_SIZE) buffer.shift();
    emitter.emit('event', enriched);
}

// ---------------------------------------------------------------------------
// Subscriptions — register once at module load
// ---------------------------------------------------------------------------

const SOURCES = [
    { queue: 'feed-sync',       events: feedSyncEvents },
    { queue: 'ioc-enrichment',  events: enrichmentEvents },
    { queue: 'ai-analysis',     events: aiAnalysisEvents },
    { queue: 'notifications',   events: notificationEvents },
    { queue: 'alerts',          events: alertsEvents },
    { queue: 'neo4j-sync',      events: neo4jSyncEvents },
    { queue: 'cve-enrichment',  events: cveEnrichmentEvents },
    { queue: 'maintenance',     events: maintenanceEvents },
] as const;

let subscribed = false;

export function ensureSubscribed() {
    if (subscribed) return;
    subscribed = true;

    for (const { queue, events } of SOURCES) {
        events.on('active', (args: { jobId: string }) => {
            record({ queue, jobId: args.jobId, kind: 'active' });
        });

        events.on('completed', (args: { jobId: string; returnvalue: unknown }) => {
            record({
                queue,
                jobId: args.jobId,
                kind: 'completed',
                result: args.returnvalue,
            });
        });

        events.on('failed', (args: { jobId: string; failedReason: string }) => {
            record({
                queue,
                jobId: args.jobId,
                kind: 'failed',
                error: args.failedReason?.slice(0, 240),
            });
        });

        events.on('progress', (args: { jobId: string; data: unknown }) => {
            record({
                queue,
                jobId: args.jobId,
                kind: 'progress',
                progress: args.data,
            });
        });
    }

    log.info('Job activity stream subscribed', { sources: SOURCES.length });
}

// Subscribe immediately on import (idempotent).
ensureSubscribed();

// ---------------------------------------------------------------------------
// Public read API
// ---------------------------------------------------------------------------

export function getRecentActivity(opts: {
    limit?: number;
    queue?: string;
    sinceSeq?: number;
} = {}): ActivityEvent[] {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), RECENT_BUFFER_SIZE);
    let rows = buffer;
    if (opts.queue) rows = rows.filter(r => r.queue === opts.queue);
    if (opts.sinceSeq !== undefined) rows = rows.filter(r => r.seq > opts.sinceSeq!);
    // Newest first.
    return rows.slice(-limit).reverse();
}

// ---------------------------------------------------------------------------
// Failure grouping
// ---------------------------------------------------------------------------

export interface FailureGroup {
    /** Normalised signature used to group similar errors (≤80 chars). */
    signature: string;
    /** First 240 chars of the most recent matching error — verbatim. */
    sample: string;
    /** Number of matching failed events in the current buffer. */
    count: number;
    /** Distinct queues these failures came from. */
    queues: string[];
    firstSeen: string;
    lastSeen: string;
}

/**
 * Strip the most common sources of "same error, different details" so a
 * rate-limit storm groups under one signature instead of 50 unique rows.
 *
 * Heuristic — not perfect, but covers the common cases we see in CTI feeds:
 *   • Dates and ISO timestamps        → <ts>
 *   • UUIDs                            → <id>
 *   • IPv4 addresses                   → <ip>
 *   • Hex hashes (8+ chars)            → <hash>
 *   • URLs (host + path)               → <url>
 *   • Trailing numeric IDs after ':'   → :<n>
 */
function normaliseErrorSignature(raw: string): string {
    return raw
        .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, '<ts>')
        .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<id>')
        .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '<ip>')
        .replace(/\bhttps?:\/\/[^\s'"]+/g, '<url>')
        .replace(/\b[0-9a-f]{8,}\b/gi, '<hash>')
        .replace(/:\d+(\b|$)/g, ':<n>$1')
        .trim()
        .slice(0, 80);
}

export function getFailureGroups(): FailureGroup[] {
    const groups = new Map<string, FailureGroup>();
    for (const evt of buffer) {
        if (evt.kind !== 'failed' || !evt.error) continue;
        const signature = normaliseErrorSignature(evt.error);
        const existing = groups.get(signature);
        if (existing) {
            existing.count++;
            if (!existing.queues.includes(evt.queue)) existing.queues.push(evt.queue);
            if (evt.ts > existing.lastSeen) {
                existing.lastSeen = evt.ts;
                existing.sample = evt.error.slice(0, 240);
            }
            if (evt.ts < existing.firstSeen) existing.firstSeen = evt.ts;
        } else {
            groups.set(signature, {
                signature,
                sample: evt.error.slice(0, 240),
                count: 1,
                queues: [evt.queue],
                firstSeen: evt.ts,
                lastSeen: evt.ts,
            });
        }
    }
    // Sort by count desc, then most-recent first as tiebreak.
    return Array.from(groups.values()).sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        return b.lastSeen.localeCompare(a.lastSeen);
    });
}

export function getThroughputStats(): ThroughputStats[] {
    const byQueue = new Map<string, ThroughputStats>();
    for (const { queue } of SOURCES) {
        byQueue.set(queue, {
            queue,
            total: 0,
            byKind: { active: 0, completed: 0, failed: 0, progress: 0 },
            lastAt: null,
        });
    }
    for (const evt of buffer) {
        const s = byQueue.get(evt.queue);
        if (!s) continue;
        s.total++;
        s.byKind[evt.kind]++;
        if (!s.lastAt || evt.ts > s.lastAt) s.lastAt = evt.ts;
    }
    return Array.from(byQueue.values()).sort((a, b) => b.total - a.total);
}

/**
 * Subscribe to live events. Returns an unsubscribe function — callers MUST
 * call it to avoid leaks (the SSE endpoint does this on stream.onAbort).
 */
export function subscribeLive(handler: (evt: ActivityEvent) => void): () => void {
    emitter.on('event', handler);
    return () => emitter.off('event', handler);
}
