/**
 * GET /v1/admin/services — Consolidated service-health view for the
 * dashboard's admin page. Aggregates datastore connectivity, AI provider
 * configuration, optional-service availability, BullMQ queue depths,
 * worker liveness, and recent feed-sync state — all in one round trip so
 * the page can render without 6 parallel calls.
 */

import { Hono } from 'hono';
import { sql } from '@rinjani/db';
import { db } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { checkRedisHealth } from '../../services/redis';
import { allQueues, getQueueStats } from '../../queues/stats';
import { getBootLockOwner } from '../../lib/bootlock';
import { createLogger } from '../../lib/logger';

const log = createLogger('AdminServices');
const router = new Hono();

router.use('*', requireAuth, requireRole('admin'));

router.get('/services', async (c) => {
    // Fire all probes in parallel — the slowest gates the response.
    const [
        postgres,
        opensearchHealth,
        redisHealth,
        neo4jHealth,
        queueStats,
        workersByQueue,
        bootlock,
        feedHealth,
        optionalServices,
        enrichmentSources,
    ] = await Promise.all([
        probePostgres(),
        probeOpenSearch(),
        checkRedisHealth().catch(() => ({ queue: { connected: false }, cache: { connected: false } })),
        probeNeo4j(),
        getQueueStats().catch(() => []),
        probeWorkers(),
        // Fallback shape must mirror `getBootLockOwner`'s return so the
        // response builder below can read `bootlock.state` / `bootlock.error`
        // off either arm. `state: 'error'` is the "Redis was unreachable
        // even at the probe-wrapping layer" signal — distinct from the
        // function's own error branch which sets the same state.
        getBootLockOwner().catch(() => ({
            owner: null,
            self: '?',
            isUs: false,
            state: 'error' as const,
            error: 'probe threw before getBootLockOwner could classify',
        })),
        probeFeedHealth(),
        probeOptionalServices(),
        probeEnrichmentSources(),
    ]);

    const llm = {
        gemini: { configured: !!(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY) },
        openrouter: { configured: !!process.env.OPENROUTER_API_KEY },
        ollama: { available: true /* always reachable if URL set; tested per-call */ },
    };

    // Worker liveness: ANY queue with > 0 connected workers means the worker
    // process is up. Bootlock alone isn't sufficient — the gateway also
    // holds the lock and schedules jobs, but only the worker EXECUTES them.
    const totalWorkers = workersByQueue.reduce((s, q) => s + q.workerCount, 0);
    const workerActive = totalWorkers > 0;

    return c.json({
        success: true,
        data: {
            process: {
                bootlockOwner: bootlock.owner,
                bootlockHeldByThisProcess: bootlock.isUs,
                // `state` distinguishes a real "no one holds it right now"
                // (background services orphaned, reclaim poller will retry)
                // from a "Redis is unreachable, we can't tell". The dashboard
                // uses this to render an actionable message instead of just
                // "Nobody holds the lock".
                bootlockState: bootlock.state,
                bootlockError: bootlock.error,
                workerActive,
                totalConnectedWorkers: totalWorkers,
                workersByQueue,
            },
            datastores: {
                postgres,
                opensearch: opensearchHealth,
                redis: redisHealth,
                neo4j: neo4jHealth,
            },
            llm,
            optionalServices,
            enrichmentSources,
            queues: queueStats,
            feeds: feedHealth,
            timestamp: new Date().toISOString(),
        },
    });
});

/* -------------------------------------------------------------------------- */
/* Per-service probes                                                         */
/* -------------------------------------------------------------------------- */

async function probePostgres(): Promise<{ connected: boolean; latencyMs?: number; error?: string }> {
    const t0 = Date.now();
    try {
        await db.execute(sql`SELECT 1`);
        return { connected: true, latencyMs: Date.now() - t0 };
    } catch (err) {
        return { connected: false, error: (err as Error).message };
    }
}

async function probeOpenSearch(): Promise<{ connected: boolean; latencyMs?: number; status?: string; error?: string }> {
    const t0 = Date.now();
    try {
        const { getOpenSearchClient } = await import('../../services/opensearch/client');
        const c = getOpenSearchClient();
        const r = await c.cluster.health();
        return { connected: true, latencyMs: Date.now() - t0, status: r.body?.status };
    } catch (err) {
        return { connected: false, error: (err as Error).message };
    }
}

async function probeNeo4j(): Promise<{ connected: boolean; latencyMs?: number; serverInfo?: string; error?: string }> {
    const t0 = Date.now();
    try {
        // checkNeo4jHealth is the real export from services/neo4j/driver.ts —
        // re-exported via services/neo4j.ts barrel. An earlier version of this
        // probe looked for a non-existent `checkHealth` and always returned
        // "no health probe", which silently broke the dashboard Datastores
        // panel for Neo4j even when the driver was healthy.
        const { checkNeo4jHealth } = await import('../../services/neo4j');
        const r = await checkNeo4jHealth();
        return {
            connected: r.connected,
            latencyMs: Date.now() - t0,
            ...(r.serverInfo ? { serverInfo: r.serverInfo } : {}),
        };
    } catch (err) {
        return { connected: false, error: (err as Error).message };
    }
}

/**
 * Per-queue worker counts via BullMQ's getWorkers(). A worker is "connected"
 * if it has registered with the queue's Redis blocking-list within ~30s.
 * If the apps/worker process is down, every queue returns 0.
 */
async function probeWorkers(): Promise<Array<{ queue: string; workerCount: number }>> {
    return Promise.all(allQueues.map(async (q) => {
        try {
            const workers = await q.getWorkers();
            return { queue: q.name, workerCount: workers.length };
        } catch (err) {
            log.debug('queue.getWorkers failed', { queue: q.name, error: (err as Error).message });
            return { queue: q.name, workerCount: 0 };
        }
    }));
}

interface FeedHealthRow {
    feed: string;
    /** Registry key the worker accepts via /admin/jobs/feed-sync. Null when
     *  the sync_logs entity_type doesn't map to a known handler. */
    registryKey: string | null;
    lastSync: string | null;
    status: string;
    itemsProcessed: number;
    itemsFailed: number;
    errorMessage: string | null;
}

/**
 * sync_logs.entity_type uses display names (alienvault_pulses, cisa_kev,
 * misp_galaxy); the feedRegistry keys differ. Map display → registry so the
 * dashboard "Sync now" button can hit /admin/jobs/feed-sync with the right
 * source value without the frontend having to know the alias table.
 */
const FEED_NAME_TO_REGISTRY: Record<string, string> = {
    alienvault_pulses: 'otx',
    cisa_kev: 'cisa',
    misp_galaxy: 'mispgalaxy',
};

async function probeFeedHealth(): Promise<FeedHealthRow[]> {
    try {
        const { getRegisteredFeeds } = await import('../../services/feedSync/feedRegistry');
        const registered = new Set(getRegisteredFeeds());

        const rows = await db.execute(sql`
            SELECT DISTINCT ON (entity_type)
                entity_type AS feed,
                last_sync_cursor,
                status,
                items_processed,
                items_failed,
                error_message,
                completed_at AS last_sync
            FROM sync_logs
            ORDER BY entity_type, completed_at DESC NULLS LAST
        `) as unknown as Array<Record<string, unknown>>;
        return rows.map(r => {
            const feed = String(r.feed ?? '');
            const key = FEED_NAME_TO_REGISTRY[feed] ?? (registered.has(feed) ? feed : null);
            return {
                feed,
                registryKey: key,
                lastSync: r.last_sync ? new Date(r.last_sync as string).toISOString() : null,
                status: String(r.status ?? 'unknown'),
                itemsProcessed: Number(r.items_processed ?? 0),
                itemsFailed: Number(r.items_failed ?? 0),
                errorMessage: (r.error_message as string) || null,
            };
        });
    } catch (err) {
        log.warn('probeFeedHealth failed', { error: (err as Error).message });
        return [];
    }
}

async function probeOptionalServices(): Promise<Record<string, { available: boolean; configured: boolean }>> {
    const probes: Array<[string, () => Promise<boolean>]> = [
        ['vault',       async () => (await import('../../services/vault')).secrets.isAvailable()],
        ['keycloak',    async () => (await import('../../services/keycloak')).keycloak.isAvailable()],
    ];

    const out: Record<string, { available: boolean; configured: boolean }> = {};
    await Promise.all(probes.map(async ([name, fn]) => {
        try {
            const available = await fn();
            out[name] = { available, configured: available }; // collapsed for simplicity
        } catch {
            out[name] = { available: false, configured: false };
        }
    }));
    return out;
}

/* -------------------------------------------------------------------------- */
/* Enrichment sources — primary (OSV) + fallback (NVD).                       */
/* These are first-class services in the CVE enrichment pipeline, not         */
/* generic "optional" integrations. The dashboard renders them in their       */
/* own card.                                                                  */
/* -------------------------------------------------------------------------- */

export interface EnrichmentSourceProbe {
    available: boolean;
    configured: boolean;
    latencyMs?: number;
    /** Optional human-readable note, e.g. "no API key — 5 req/30s limit". */
    note?: string;
    error?: string;
}

async function probeEnrichmentSources(): Promise<Record<string, EnrichmentSourceProbe>> {
    return {
        osv: await probeOsv(),
        nvd: probeNvdConfig(),  // sync — no active API hit (rate-limit pressure)
    };
}

/**
 * Probe OSV by fetching a well-known CVE (log4shell). OSV is public, no auth,
 * no rate limit — a 5s timeout is plenty.
 */
async function probeOsv(): Promise<EnrichmentSourceProbe> {
    const t0 = Date.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5_000);
    try {
        const res = await fetch('https://api.osv.dev/v1/vulns/CVE-2021-44228', {
            signal: ctrl.signal,
            headers: { 'Accept': 'application/json' },
        });
        return {
            available: res.ok,
            configured: true,                 // OSV requires no configuration
            latencyMs: Date.now() - t0,
            ...(res.ok ? {} : { error: `HTTP ${res.status}` }),
        };
    } catch (err) {
        return {
            available: false,
            configured: true,
            error: (err as Error).message,
        };
    } finally {
        clearTimeout(timer);
    }
}

/**
 * NVD is *always* reachable without a key (just slow). We don't actively
 * probe to avoid burning rate-limit budget — instead we report key
 * presence and a note about the consequence.
 */
function probeNvdConfig(): EnrichmentSourceProbe {
    const hasKey = !!(process.env.CVE_API_KEY || process.env.NVD_API_KEY);
    return {
        available: true,
        configured: hasKey,
        note: hasKey
            ? '50 req/30s with API key'
            : 'no API key — 5 req/30s limit, used as OSV fallback',
    };
}

export default router;
