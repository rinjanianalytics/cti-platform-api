/**
 * Background Service Bootstrap
 *
 * Starts all background services (scheduler, DB listener, workers,
 * web search worker, graceful shutdown handler, scheduled jobs).
 * Called once after the HTTP server starts.
 *
 * Guarded by a cross-process Redis advisory lock (see `lib/bootlock.ts`)
 * so concurrent api + gateway processes don't both boot the same services
 * — which used to double load on Postgres, OpenSearch, and Gemini.
 */

import { createLogger } from './lib/logger';
import { tryAcquireBootLock, releaseBootLock, startBootLockReclaim } from './lib/bootlock';

const log = createLogger('Boot');

export async function bootServices(): Promise<void> {
    // Cross-process guard: if another instance already booted these services,
    // skip ours. Graceful shutdown below releases the lock for the next holder.
    const owns = await tryAcquireBootLock();
    if (!owns) {
        // Still want SIGTERM/SIGINT to close DB/Redis connections cleanly,
        // even though we never booted background services here.
        setupGracefulShutdown();
        // If the previous holder dies without a graceful release (notably
        // tsx-watch SIGKILLing on reload), the 30s TTL eventually expires and
        // services would stay orphaned. Poll for reclaim so this process can
        // pick up where the dead one left off.
        startBootLockReclaim(() => bootOwnerOnlyServices());
        return;
    }
    await bootOwnerOnlyServices();
}

/**
 * Everything below was originally inline in `bootServices`. It's the set of
 * services that should run in exactly ONE process across the api+gateway
 * pair — migrations, worker pool, scheduler, feed-sync daemon, etc. Pulled
 * out so the reclaim path can run the same block when a non-owner process
 * later acquires the lock (see `startBootLockReclaim` in `lib/bootlock.ts`).
 */
async function bootOwnerOnlyServices(): Promise<void> {

    // Run pending database migrations before anything else
    import('./services/migrations').then(({ autoMigrateOnStartup }) => {
        autoMigrateOnStartup();
    }).catch(err => {
        log.warn('Auto-migrate failed', { error: err.message });
    });

    // Ensure all built-in feeds, API keys, and services exist in config tables
    import('./services/configBootstrap').then(({ ensureBuiltInIntegrations }) => {
        ensureBuiltInIntegrations();
    }).catch(err => {
        log.warn('Config bootstrap failed', { error: err.message });
    });

    // Ensure all built-in roles (admin, analyst, developer, auditor, viewer) exist
    import('./services/userService').then(({ ensureBuiltInRoles }) => {
        ensureBuiltInRoles();
    }).catch(err => {
        log.warn('Role bootstrap failed', { error: err.message });
    });

    // ── Platform service availability checks (optional services) ──────────
    // Probe all four in parallel, then emit a single summary line. Reduces
    // boot-log noise from 4 INFO lines (one per service) to 1.
    Promise.all([
        import('./services/vault')
            .then(m => m.secrets.isAvailable().then(ok => ({ name: 'Vault', ok })))
            .catch(() => ({ name: 'Vault', ok: false })),
        import('./services/keycloak')
            .then(m => m.keycloak.isAvailable().then(ok => ({ name: 'Keycloak', ok })))
            .catch(() => ({ name: 'Keycloak', ok: false })),
    ]).then(results => {
        const active = results.filter(r => r.ok).map(r => r.name);
        const skipped = results.filter(r => !r.ok).map(r => r.name);
        log.info(`Optional services: ${active.length}/${results.length} active`, {
            active: active.length ? active : undefined,
            skipped: skipped.length ? skipped : undefined,
        });
    });

    // Start SSE event bus (Redis Pub/Sub)
    import('./services/eventBus').then(({ eventBus }) => {
        eventBus.start();
    }).catch(err => {
        log.warn('EventBus failed to start', { error: err.message });
    });

    // Start Redis Streams event-driven architecture (durable event bus)
    Promise.all([
        import('./services/eventStream'),
        import('./queues/streamConsumers'),
    ]).then(([{ eventStream }, consumers]) => {
        eventStream.start().then(() => {
            // Register all consumer groups
            eventStream.startConsumer({
                group: 'enrichment-group',
                consumer: 'enrichment-1',
                streams: ['ioc'],
                handler: consumers.handleEnrichment,
                batchSize: 20,
            });

            eventStream.startConsumer({
                group: 'opensearch-group',
                consumer: 'opensearch-1',
                streams: ['ioc', 'vuln', 'actor', 'enrichment'],
                handler: consumers.handleOpenSearchSync,
                batchSize: 50,
            });

            eventStream.startConsumer({
                group: 'neo4j-group',
                consumer: 'neo4j-1',
                streams: ['ioc', 'vuln', 'actor'],
                handler: consumers.handleNeo4jSync,
                batchSize: 20,
            });

            eventStream.startConsumer({
                group: 'alert-group',
                consumer: 'alert-1',
                streams: ['ioc', 'enrichment'],
                handler: consumers.handleAlertEvaluation,
                batchSize: 50,
            });

            eventStream.startConsumer({
                group: 'taxii-group',
                consumer: 'taxii-1',
                streams: ['ioc', 'actor', 'enrichment'],
                handler: consumers.handleTaxiiPublish,
                batchSize: 30,
            });

            // Audit trail — capture all entity events for audit_logs table
            eventStream.startConsumer({
                group: 'audit-group',
                consumer: 'audit-1',
                streams: ['ioc', 'vuln', 'actor', 'enrichment', 'system'],
                handler: consumers.handleAuditLog,
                batchSize: 50,
            });

            log.info('All stream consumers registered (6 groups)');
        });
    }).catch(err => {
        log.warn('EventStream failed to start', { error: err.message });
    });

    // Start background scheduler for periodic reindexing
    import('./services/scheduler').then(({ startScheduler }) => {
        startScheduler();
    }).catch(err => {
        log.warn('Scheduler failed to start', { error: err.message });
    });

    // Start PostgreSQL listener for real-time OpenSearch sync
    import('./services/db-listener').then(({ startDBListener }) => {
        startDBListener();
    }).catch(err => {
        log.warn('DB-Listener failed to start', { error: err.message });
    });

    // ── BullMQ workers, scheduler, work listener, feed-sync daemon ──────
    //
    // These used to live in apps/worker/src/worker-entry.ts as a separate
    // Node process for independent scaling. Merged in-process so a single
    // `pnpm dev` starts everything. Trade noted in the commit message:
    // workers now share event-loop time with HTTP handling, and a
    // worker-side crash takes the API down with it. The bootlock above
    // still gates this block, so concurrent api instances don't all try
    // to start workers — only the lock-holder does.
    Promise.all([
        import('./queues/workers/workerEvents'),
        import('./queues/scheduler'),
        import('./services/workListener'),
    ]).then(async ([{ startWorkers }, { setupScheduledJobs }, { startWorkListener, triggerEnrichmentSweep }]) => {
        try {
            startWorkers();
            log.info('BullMQ workers started');
        } catch (err) {
            log.error('startWorkers failed', err as Error);
        }

        try {
            await setupScheduledJobs();
            log.info('Scheduled BullMQ jobs configured');
        } catch (err) {
            log.warn('setupScheduledJobs failed', { error: (err as Error).message });
        }

        try {
            await startWorkListener();
            log.info('Work-driven enrichment listener active');
            // Boot-time backstop sweeps — catch anything that landed while
            // the process was offline.
            const cve = await triggerEnrichmentSweep('cve-enrich');
            log.info('CVE-enrich backstop sweep queued', { jobId: cve.jobId });
            const ioc = await triggerEnrichmentSweep('ioc-enrich');
            log.info('IOC-enrich backstop sweep queued', { enqueued: ioc.enqueued });
        } catch (err) {
            log.warn('Work listener setup failed', { error: (err as Error).message });
        }
    }).catch(err => {
        log.error('Worker subsystem boot failed', err as Error);
    });

    // ── Feed-sync setInterval daemon ────────────────────────────────────
    // Legacy parallel path to the BullMQ scheduled-jobs feed-sync flow.
    // Kept for behavioural parity with the old worker-entry; consider
    // removing once /admin/schedules ownership is the only path used.
    // Opt out with `ENABLE_FEED_SYNC=false`.
    if (process.env.ENABLE_FEED_SYNC !== 'false') {
        import('../../worker/src/feeds/index').then(({ feeds, runAllFeeds }) => {
            const names = Object.keys(feeds);
            log.info(`Feed-sync daemon: ${names.length} feeds`, {
                feeds: names.map(k => `${feeds[k as keyof typeof feeds].name}@${feeds[k as keyof typeof feeds].interval / 60000}min`),
            });
            runAllFeeds().catch(err => log.error('Initial feed sync failed', err as Error));
            for (const [, feed] of Object.entries(feeds)) {
                setInterval(async () => {
                    try {
                        await feed.sync();
                    } catch (err) {
                        log.error(`Feed sync failed: ${feed.name}`, err as Error);
                    }
                }, feed.interval);
            }
        }).catch(err => {
            log.warn('Feed-sync daemon disabled (import failed)', { error: (err as Error).message });
        });
    }

    setupGracefulShutdown();

    // Register playbook evaluator as webhook event listener
    Promise.all([
        import('@rinjani/core/webhooks'),
        import('./services/playbooks'),
    ]).then(([{ addWebhookEventListener }, { evaluatePlaybooks }]) => {
        addWebhookEventListener(async (event, data) => {
            try {
                await evaluatePlaybooks(event, data);
            } catch (err) {
                log.warn('Playbook evaluation failed', { event, error: (err as Error).message });
            }
        });
        log.info('Playbook event listener registered');
    }).catch(err => {
        log.warn('Failed to register playbook event listener', { error: err.message });
    });
}

/**
 * Idempotent shutdown wiring — safe to call from both owner and non-owner
 * paths. Closes DB + Redis pools and releases the bootlock if we hold it
 * so the next process can grab it without waiting for the 30s TTL.
 */
let shutdownWired = false;
function setupGracefulShutdown(): void {
    if (shutdownWired) return;
    shutdownWired = true;

    Promise.all([
        import('./lib/db/clients'),
        import('./services/redis'),
        import('./services/eventBus'),
        import('./services/eventStream'),
        // Workers + work listener are best-effort during shutdown — if the
        // import failed at boot we still want SIGTERM to drain the DB pool.
        import('./queues/workers/workerEvents').catch(() => null),
        import('./services/workListener').catch(() => null),
    ]).then(([{ shutdownAll }, { shutdownRedis }, { eventBus }, { eventStream }, workerEvents, workListener]) => {
        const shutdown = async (signal: string) => {
            log.info(`Received ${signal}, shutting down gracefully...`);
            // Release bootlock FIRST so the next process can claim it
            // before we tear down the Redis connection.
            await releaseBootLock();
            // Stop workers + work listener before tearing down Redis so
            // they can finish their in-flight jobs / close their BullMQ
            // connections cleanly.
            await Promise.allSettled([
                workerEvents?.stopWorkers?.(),
                workListener?.stopWorkListener?.(),
            ]);
            await Promise.allSettled([
                shutdownAll(),
                shutdownRedis(),
                eventBus.shutdown(),
                eventStream.shutdown(),
            ]);
            log.info('All connections closed, exiting');
            process.exit(0);
        };
        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));
    }).catch(err => {
        log.warn('Failed to setup graceful shutdown', { error: err.message });
    });
}
