import { Worker, Job } from 'bullmq';
import { and, eq, gte, inArray, db } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { connection } from '../../services/redis';
import { getFeedHandler, getRegisteredFeeds } from '../../services/feedSync/feedRegistry';
import type { FeedSyncJobData } from '../types';
import { flowProducer } from '../definitions';
import { createLogger } from '../../lib/logger';
import {
    getConfig, getFeedById,
    beginFeedSyncRun, completeFeedSyncRun,
} from '../../services/configStore';

const AUTO_ENRICH_CONFIG = {
    enabled: process.env.AUTO_ENRICH_ENABLED === 'true', // opt-IN: set AUTO_ENRICH_ENABLED=true to enable
    batchSize: parseInt(process.env.AUTO_ENRICH_BATCH_SIZE || '50', 10),
    priorityTypes: ['ip', 'domain', 'hash', 'url'],
    delayMs: 500,
};

export const feedSyncWorker = new Worker<FeedSyncJobData>(
    'feed-sync',
    async (job: Job<FeedSyncJobData>) => {
        const log = createLogger('FeedSync');

        // Check if feed sync is disabled via dashboard toggle
        const enabled = await getConfig('FEED_SYNC_ENABLED');
        if (enabled === 'false') {
            log.info('Feed sync disabled via settings, skipping', { jobId: job.id, source: job.data.source });
            return { skipped: true, reason: 'Feed sync disabled via settings' };
        }

        log.info('Processing job', { jobId: job.id, source: job.data.source });

        const { source, options } = job.data;
        let result;
        const newIOCs: Array<{ id: string; value: string; type: string }> = [];

        // Open a feed_sync_runs row before any work — the flow parent
        // needs this id to write back enriched_at when its children settle.
        // Use the BullMQ job's trigger when available so manual runs from
        // /admin/jobs get the correct provenance.
        const triggeredBy: 'scheduler' | 'manual' =
            (job.data.options as { triggeredBy?: 'scheduler' | 'manual' } | undefined)?.triggeredBy
            ?? 'scheduler';
        const runId = await beginFeedSyncRun(source, { triggeredBy });
        // Captured BEFORE the handler runs so the DB-fallback IOC lookup
        // (see "Auto-enrichment" block below) only picks up rows the
        // handler actually touched on this run.
        const runStartTime = new Date();

        try {
            await job.updateProgress(10);

            if (source === 'all') {
                // Run all registered feeds
                const sources = getRegisteredFeeds();
                log.info('Syncing all feeds', { feedCount: sources.length, feeds: sources });
                const results = await Promise.allSettled(
                    sources.map(async (s) => {
                        log.info(`[all] Starting feed: ${s}`);
                        const handler = getFeedHandler(s)!;
                        const res = await handler(options);
                        log.info(`[all] Completed feed: ${s}`, {
                            added: res.indicatorsAdded,
                            processed: res.indicatorsProcessed,
                            success: res.success,
                        });
                        return { source: s, result: res };
                    })
                );

                let totalAdded = 0;
                let totalProcessed = 0;
                let succeeded = 0;
                let failed = 0;
                const perFeed: Record<string, unknown> = {};
                for (const r of results) {
                    if (r.status === 'fulfilled') {
                        const { source: src, result: res } = r.value;
                        perFeed[src] = res;
                        totalAdded += res.indicatorsAdded;
                        totalProcessed += res.indicatorsProcessed || 0;
                        succeeded++;
                        if (res.indicators && res.indicators.length > 0) {
                            newIOCs.push(...res.indicators);
                        }
                    } else {
                        failed++;
                        log.error(`[all] Feed failed`, new Error(r.reason?.message || String(r.reason)));
                    }
                }
                log.info('All feeds sync summary', {
                    succeeded, failed, totalAdded, totalProcessed,
                });
                result = {
                    ...perFeed,
                    indicatorsAdded: totalAdded,
                    indicatorsProcessed: totalProcessed,
                };
            } else {
                // Check if specific feed is enabled in DB
                const feedConfig = await getFeedById(source);
                if (feedConfig && !feedConfig.enabled) {
                    log.warn(`Feed '${source}' is disabled — skipping job`, {
                        jobId: job.id, feedId: feedConfig.id, source,
                    });
                    return { skipped: true, reason: `Feed '${source}' is disabled` };
                }

                const handler = getFeedHandler(source);
                if (!handler) {
                    log.error(`Unknown feed source: ${source}`, new Error(`No handler registered for '${source}'`), {
                        jobId: job.id, registeredFeeds: getRegisteredFeeds(),
                    });
                    throw new Error(`Unknown feed source: ${source}`);
                }

                log.info(`Dispatching feed sync: ${source}`, {
                    jobId: job.id, hasConfig: !!feedConfig, options,
                });
                result = await handler(options);
                log.info(`Feed sync completed: ${source}`, {
                    jobId: job.id, success: result.success,
                    added: result.indicatorsAdded, processed: result.indicatorsProcessed,
                    errors: result.errors?.length || 0,
                });
                if (result.indicators && result.indicators.length > 0) {
                    newIOCs.push(...result.indicators);
                }
            }

            await job.updateProgress(70);

            // Auto-enrichment — fan out as a FlowProducer batch so workbench's
            // Flows view shows one parent ("batch-<runId>") with N children.
            // The parent job (in `feed-batch` queue) settles after all children
            // complete and stamps `feed_sync_runs.enriched_at` for this run.
            //
            // DB fallback: most feed handlers (openphish, threatfox, urlhaus,
            // malwarebazaar, abuseSSL) route through `normalise()` in
            // additionalFeeds.ts, which only propagates counts — `indicators`
            // is dropped, so `newIOCs` stays empty even when 300+ rows landed
            // in the DB. When that happens AND auto-enrich is on AND the
            // sync claims to have ingested rows, we lift the recently-touched
            // IOCs straight from the DB scoped to this source + updated since
            // the run started. (We use `updatedAt` not `createdAt` so a
            // duplicate that just got its lastSeen bumped also surfaces for
            // re-enrichment if its priority type qualifies.)
            let enrichmentJobsQueued = 0;
            if (
                AUTO_ENRICH_CONFIG.enabled &&
                newIOCs.length === 0 &&
                source !== 'all' &&
                ((result as { indicatorsAdded?: number })?.indicatorsAdded ?? 0) > 0
            ) {
                const recent = await db
                    .select({ id: iocs.id, value: iocs.value, type: iocs.type })
                    .from(iocs)
                    .where(
                        and(
                            eq(iocs.source, source),
                            gte(iocs.updatedAt, runStartTime),
                            inArray(iocs.type, AUTO_ENRICH_CONFIG.priorityTypes),
                        ),
                    )
                    .limit(AUTO_ENRICH_CONFIG.batchSize);
                newIOCs.push(...recent);
                log.info('Auto-enrichment: DB fallback found recent IOCs', {
                    source,
                    count: recent.length,
                });
            }

            if (AUTO_ENRICH_CONFIG.enabled && newIOCs.length > 0) {
                const iocsToEnrich = newIOCs
                    .filter(ioc => AUTO_ENRICH_CONFIG.priorityTypes.includes(ioc.type))
                    .slice(0, AUTO_ENRICH_CONFIG.batchSize);

                if (iocsToEnrich.length > 0) {
                    log.info('Auto-enrichment: building flow', { children: iocsToEnrich.length });
                    await flowProducer.add({
                        name: `batch-${runId}`,
                        queueName: 'feed-batch',
                        data: { runId, source, ingestedCount: iocsToEnrich.length },
                        children: iocsToEnrich.map((ioc, i) => ({
                            name: `auto-enrich-${ioc.id}`,
                            queueName: 'ioc-enrichment',
                            data: {
                                iocId: ioc.id,
                                iocValue: ioc.value,
                                iocType: ioc.type,
                                sources: ['virustotal', 'geoip'],
                            },
                            opts: {
                                delay: i * AUTO_ENRICH_CONFIG.delayMs,
                                priority: 5,
                            },
                        })),
                    });
                    enrichmentJobsQueued = iocsToEnrich.length;
                    log.info('Auto-enrichment flow queued', { runId, children: enrichmentJobsQueued });
                }
            }

            await job.updateProgress(100);

            const { success: _, ...syncData } = (result || {}) as Record<string, unknown>;

            await completeFeedSyncRun(runId, {
                status: 'completed',
                itemsIngested: (syncData.indicatorsAdded as number) ?? newIOCs.length,
                errors: (syncData.errors as unknown[])?.length ?? 0,
                enrichmentChildrenTotal: enrichmentJobsQueued,
            });

            return {
                success: true,
                source,
                runId,
                processedAt: new Date().toISOString(),
                autoEnrichmentJobsQueued: enrichmentJobsQueued,
                ...syncData,
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id, runId });
            await completeFeedSyncRun(runId, {
                status: 'failed',
                itemsIngested: newIOCs.length,
                errors: 1,
                errorDetails: (error as Error).message.slice(0, 1000),
                enrichmentChildrenTotal: 0,
            }).catch(err => log.warn('failed to mark run as failed', { err: (err as Error).message }));

            await job.updateData({
                ...job.data,
                _errorMeta: {
                    message: (error as Error).message,
                    stack: (error as Error).stack?.split('\n').slice(0, 5).join('\n'),
                    attemptsMade: job.attemptsMade + 1,
                    failedAt: new Date().toISOString(),
                },
            } as FeedSyncJobData & { _errorMeta: { message: string; stack?: string; attemptsMade: number; failedAt: string } });
            throw error;
        }
    },
    {
        connection,
        concurrency: 2,
    }
);
