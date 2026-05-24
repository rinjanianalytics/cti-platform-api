/**
 * Admin SSE Event Streams
 *
 * Server-Sent Events for real-time queue monitoring.
 * Resilient to Redis/BullMQ being unavailable — falls back to
 * heartbeat-only mode when queues can't be connected.
 */

import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import type { QueueEvents } from 'bullmq';

const router = new Hono();

// ============================================================================
// Lazy-load queue events (resilient to Redis being unavailable)
// ============================================================================

interface QueueEventSources {
    feedSyncEvents: QueueEvents;
    enrichmentEvents: QueueEvents;
    aiAnalysisEvents: QueueEvents;
    notificationEvents: QueueEvents;
    alertsEvents: QueueEvents;
    neo4jSyncEvents: QueueEvents;
    getQueueStats: () => Promise<unknown>;
}

let queueEvents: QueueEventSources | null = null;
let queueLoadAttempted = false;

async function getQueueEvents(): Promise<QueueEventSources | null> {
    if (queueLoadAttempted) return queueEvents;
    queueLoadAttempted = true;

    try {
        const mod = await import('../../queues');
        queueEvents = {
            feedSyncEvents: mod.feedSyncEvents,
            enrichmentEvents: mod.enrichmentEvents,
            aiAnalysisEvents: mod.aiAnalysisEvents,
            notificationEvents: mod.notificationEvents,
            alertsEvents: mod.alertsEvents,
            neo4jSyncEvents: mod.neo4jSyncEvents,
            getQueueStats: mod.getQueueStats,
        };
    } catch {
        // Redis/BullMQ unavailable — fallback to heartbeat-only mode
        queueEvents = null;
    }

    return queueEvents;
}

// ============================================================================
// GET /events — SSE stream for real-time queue updates
// ============================================================================

router.get('/events', async (c) => {
    // Accept auth from query param (EventSource can't set headers)
    // optionalAuth already handles ?api_key= in the global middleware

    return streamSSE(c, async (stream) => {
        const events = await getQueueEvents();

        const sendEvent = async (type: string, data: Record<string, unknown>) => {
            await stream.writeSSE({
                event: type,
                data: JSON.stringify(data),
            });
        };

        // Send initial connection message
        await sendEvent('connected', {
            message: 'SSE stream connected',
            timestamp: new Date().toISOString(),
            queuesAvailable: events !== null,
        });

        // Register queue event listeners (if queues are available)
        const cleanupFns: Array<() => void> = [];

        if (events) {
            const onFeedCompleted = async (args: { jobId: string; returnvalue: unknown }) => {
                await sendEvent('feed.completed', { jobId: args.jobId, result: args.returnvalue });
            };
            const onFeedFailed = async (args: { jobId: string; failedReason: string }) => {
                await sendEvent('feed.failed', { jobId: args.jobId, error: args.failedReason });
            };
            const onEnrichCompleted = async (args: { jobId: string; returnvalue: unknown }) => {
                await sendEvent('enrichment.completed', { jobId: args.jobId, result: args.returnvalue });
            };
            const onAnalysisCompleted = async (args: { jobId: string; returnvalue: unknown }) => {
                await sendEvent('analysis.completed', { jobId: args.jobId, result: args.returnvalue });
            };
            const onNotificationCompleted = async (args: { jobId: string; returnvalue: unknown }) => {
                await sendEvent('notification.completed', { jobId: args.jobId, result: args.returnvalue });
            };
            const onAlertCompleted = async (args: { jobId: string; returnvalue: unknown }) => {
                await sendEvent('alert.new', { jobId: args.jobId, alert: args.returnvalue });
            };

            events.feedSyncEvents.on('completed', onFeedCompleted);
            events.feedSyncEvents.on('failed', onFeedFailed);
            events.enrichmentEvents.on('completed', onEnrichCompleted);
            events.aiAnalysisEvents.on('completed', onAnalysisCompleted);
            events.notificationEvents.on('completed', onNotificationCompleted);
            events.alertsEvents.on('completed', onAlertCompleted);

            cleanupFns.push(() => {
                events.feedSyncEvents.off('completed', onFeedCompleted);
                events.feedSyncEvents.off('failed', onFeedFailed);
                events.enrichmentEvents.off('completed', onEnrichCompleted);
                events.aiAnalysisEvents.off('completed', onAnalysisCompleted);
                events.notificationEvents.off('completed', onNotificationCompleted);
                events.alertsEvents.off('completed', onAlertCompleted);
            });
        }

        // Heartbeat every 30s
        const heartbeat = setInterval(async () => {
            try {
                await sendEvent('heartbeat', { timestamp: new Date().toISOString() });
            } catch {
                clearInterval(heartbeat);
            }
        }, 30000);

        // Cleanup on disconnect
        stream.onAbort(() => {
            clearInterval(heartbeat);
            cleanupFns.forEach(fn => fn());
        });

        // Keep stream open
        await new Promise(() => { });
    });
});

// ============================================================================
// GET /pipeline-events — Full pipeline lifecycle SSE stream
// ============================================================================

const PIPELINE_QUEUE_NAMES = [
    { name: 'feed-sync', key: 'feedSyncEvents' as const, color: '#22c55e' },
    { name: 'ioc-enrichment', key: 'enrichmentEvents' as const, color: '#3b82f6' },
    { name: 'ai-analysis', key: 'aiAnalysisEvents' as const, color: '#a855f7' },
    { name: 'notifications', key: 'notificationEvents' as const, color: '#f59e0b' },
    { name: 'alerts', key: 'alertsEvents' as const, color: '#ef4444' },
    { name: 'neo4j-sync', key: 'neo4jSyncEvents' as const, color: '#06b6d4' },
];

router.get('/pipeline-events', async (c) => {
    return streamSSE(c, async (stream) => {
        const events = await getQueueEvents();

        const sendPipelineEvent = async (
            queue: string,
            event: 'active' | 'progress' | 'completed' | 'failed' | 'waiting',
            data: Record<string, unknown>,
        ) => {
            await stream.writeSSE({
                event: 'pipeline',
                data: JSON.stringify({
                    queue,
                    event,
                    timestamp: new Date().toISOString(),
                    ...data,
                }),
            });
        };

        const cleanupFns: Array<() => void> = [];

        if (events) {
            for (const q of PIPELINE_QUEUE_NAMES) {
                const queueEvents = events[q.key];
                if (!queueEvents) continue;

                const onActive = async (args: { jobId: string }) => {
                    await sendPipelineEvent(q.name, 'active', { jobId: args.jobId });
                };
                const onProgress = async (args: { jobId: string; data: unknown }) => {
                    await sendPipelineEvent(q.name, 'progress', { jobId: args.jobId, progress: args.data });
                };
                const onCompleted = async (args: { jobId: string; returnvalue: unknown }) => {
                    await sendPipelineEvent(q.name, 'completed', { jobId: args.jobId, result: args.returnvalue });
                };
                const onFailed = async (args: { jobId: string; failedReason: string }) => {
                    await sendPipelineEvent(q.name, 'failed', { jobId: args.jobId, error: args.failedReason });
                };
                const onWaiting = async (args: { jobId: string }) => {
                    await sendPipelineEvent(q.name, 'waiting', { jobId: args.jobId });
                };

                queueEvents.on('active', onActive);
                queueEvents.on('progress', onProgress);
                queueEvents.on('completed', onCompleted);
                queueEvents.on('failed', onFailed);
                queueEvents.on('waiting', onWaiting);

                cleanupFns.push(() => {
                    queueEvents.off('active', onActive);
                    queueEvents.off('progress', onProgress);
                    queueEvents.off('completed', onCompleted);
                    queueEvents.off('failed', onFailed);
                    queueEvents.off('waiting', onWaiting);
                });
            }

            // Send initial stats snapshot
            try {
                const stats = await events.getQueueStats();
                await stream.writeSSE({
                    event: 'init',
                    data: JSON.stringify({
                        queues: PIPELINE_QUEUE_NAMES.map(q => ({ name: q.name, color: q.color })),
                        stats,
                        timestamp: new Date().toISOString(),
                    }),
                });
            } catch {
                // Non-fatal
            }
        }

        // Heartbeat every 15s
        const heartbeat = setInterval(async () => {
            try {
                const stats = events ? await events.getQueueStats().catch(() => null) : null;
                await stream.writeSSE({
                    event: 'heartbeat',
                    data: JSON.stringify({ stats, timestamp: new Date().toISOString() }),
                });
            } catch {
                clearInterval(heartbeat);
            }
        }, 15000);

        stream.onAbort(() => {
            clearInterval(heartbeat);
            cleanupFns.forEach(fn => fn());
        });

        await new Promise(() => { });
    });
});

export default router;
