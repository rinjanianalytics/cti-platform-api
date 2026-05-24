/**
 * V3 Worker Entry Point — BullMQ Workers + Feed Sync
 *
 * Standalone process that runs all background job workers independently
 * of the Hono HTTP server. This enables independent scaling of
 * compute-heavy work (enrichment, AI analysis, Neo4j sync, etc.)
 * from latency-sensitive API request handling.
 *
 * Usage:
 *   pnpm --filter @rinjani/worker start:workers
 *   pnpm --filter @rinjani/worker dev:workers
 */

// MUST be the very first import — loads .env before any module that
// reads process.env at import time (Redis, BullMQ, etc.).
import './boot-env.js';

// ============================================================================
// BullMQ Workers (from apps/api/src/queues)
// ============================================================================

// Workers are defined in apps/api/src/queues/workers/ and auto-register
// their event handlers on import. We import startWorkers/stopWorkers
// to coordinate startup and graceful shutdown.
import { startWorkers, stopWorkers } from '../../api/src/queues/workers/workerEvents.js';

// Scheduled jobs (cron-like repeatable BullMQ jobs)
import { setupScheduledJobs } from '../../api/src/queues/scheduler.js';

// Work-driven enrichment dispatcher (PG NOTIFY → BullMQ).
// Replaces the daily cron wake-up for CVE enrichment: the worker fires
// whenever a row lands that needs enrichment. Includes a boot-time
// backstop sweep to catch anything missed during downtime.
import {
    startWorkListener,
    stopWorkListener,
    triggerEnrichmentSweep,
} from '../../api/src/services/workListener.js';

// Redis connection for graceful shutdown
import { shutdownRedis } from '../../api/src/services/redis.js';

// ============================================================================
// Feed Sync — Full 10-Feed Orchestrator
// ============================================================================

import { feeds, runAllFeeds, type FeedName } from './feeds/index.js';


const ENABLE_FEED_SYNC = process.env.ENABLE_FEED_SYNC !== 'false'; // enabled by default

const FEED_NAMES = Object.keys(feeds) as FeedName[];
const FEED_COUNT = FEED_NAMES.length;

// ============================================================================
// Main — Boot Everything
// ============================================================================

async function main() {
    const feedList = FEED_NAMES.map(k => `${feeds[k].name} (${feeds[k].interval / 60000}min)`).join(', ');
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║         V3 Worker Process (Standalone)                    ║
╠═══════════════════════════════════════════════════════════╣
║  BullMQ Workers:  8 (feed-sync, enrichment, AI, Neo4j,    ║
║                   CVE, notifications, alerts, retention)  ║
║  Feed Sync:       ${ENABLE_FEED_SYNC ? 'Enabled' : 'Disabled'} (${FEED_COUNT} feeds)${' '.repeat(Math.max(0, 23 - (ENABLE_FEED_SYNC ? 'Enabled' : 'Disabled').length - String(FEED_COUNT).length))}║
║  Scheduled Jobs:  cron-based repeatable jobs              ║
╚═══════════════════════════════════════════════════════════╝
`);

    console.log(`[Worker] Feed registry: ${feedList}`);

    // 1. Start all BullMQ workers
    console.log('[Worker] Starting BullMQ workers...');
    startWorkers();
    console.log('[Worker] ✅ All BullMQ workers started');

    // 2. Setup scheduled jobs (cron-like repeatable BullMQ jobs)
    console.log('[Worker] Setting up scheduled jobs...');
    try {
        await setupScheduledJobs();
        console.log('[Worker] ✅ Scheduled jobs configured');
    } catch (err) {
        console.warn('[Worker] ⚠️ Scheduled jobs setup failed:', (err as Error).message);
    }

    // 2b. Start the work-driven enrichment listener + one-shot backstop
    //     sweeps. The listener subscribes to Postgres NOTIFYs on the
    //     `rinjani_work` channel; the sweeps catch any rows that landed
    //     while the worker was offline.
    console.log('[Worker] Starting work-driven enrichment listener...');
    try {
        await startWorkListener();
        console.log('[Worker] ✅ Work listener active');

        const cveSweep = await triggerEnrichmentSweep('cve-enrich');
        console.log(`[Worker] ✅ Backstop CVE-enrich sweep queued (job ${cveSweep.jobId})`);

        const iocSweep = await triggerEnrichmentSweep('ioc-enrich');
        console.log(`[Worker] ✅ Backstop IOC-enrich sweep enqueued ${iocSweep.enqueued} row(s)`);
    } catch (err) {
        console.warn('[Worker] ⚠️ Work listener setup failed:', (err as Error).message);
    }

    // 3. Start feed sync daemon (if enabled)
    if (ENABLE_FEED_SYNC) {
        console.log(`[Worker] Starting feed sync daemon with ${FEED_COUNT} feeds...`);

        // Initial sync of all feeds on startup
        await runAllFeeds().catch(err => {
            console.error('[Worker] Initial feed sync failed:', err);
        });

        // Set up per-feed intervals (each feed runs on its own schedule)
        for (const [key, feed] of Object.entries(feeds)) {
            const intervalMin = (feed.interval / 60000).toFixed(0);
            console.log(`[Worker] Scheduling ${feed.name} every ${intervalMin}min`);
            setInterval(async () => {
                console.log(`[Worker] Scheduled sync: ${feed.name}`);
                try {
                    await feed.sync();
                } catch (error) {
                    console.error(`[Worker] Feed sync failed: ${feed.name}`, error);
                }
            }, feed.interval);
        }

        console.log(`[Worker] ✅ Feed sync daemon running (${FEED_COUNT} feeds on independent intervals)`);
    } else {
        console.log('[Worker] ⏭️  Feed sync disabled (ENABLE_FEED_SYNC=false)');
    }

    // 4. Graceful shutdown handler
    const shutdown = async (signal: string) => {
        console.log(`[Worker] Received ${signal}, shutting down gracefully...`);
        await Promise.allSettled([
            stopWorkers(),
            stopWorkListener(),
            shutdownRedis(),
        ]);
        console.log('[Worker] All workers stopped, exiting');
        process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    console.log('[Worker] ✅ Worker process fully started');
}

main().catch((error) => {
    console.error('[Worker] Fatal error:', error);
    process.exit(1);
});
