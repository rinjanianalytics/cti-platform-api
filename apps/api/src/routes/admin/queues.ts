/**
 * Admin Queue Dashboard & Management
 *
 * Bull Board UI mount, queue stats, and CRUD operations.
 */

import { Hono } from 'hono';
import { createBullBoard } from '@bull-board/api';
import { BullMQAdapter } from '@bull-board/api/bullMQAdapter';
import { HonoAdapter } from '@bull-board/hono';
import { serveStatic } from '@hono/node-server/serve-static';
import {
    feedSyncQueue,
    enrichmentQueue,
    aiAnalysisQueue,
    notificationQueue,
    alertsQueue,
    neo4jSyncQueue,
    cveEnrichmentQueue,
    maintenanceQueue,
    allQueues,
    getQueueStats,
} from '../../queues';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { AdminQueueCleanSchema, AdminQueueJobsSchema } from '../../lib/schemas';
import type { Queue } from 'bullmq';

const router = new Hono();

// ============================================================================
// Queue Lookup Helper
// ============================================================================

const queueMap: Record<string, Queue> = {
    'feed-sync': feedSyncQueue,
    'ioc-enrichment': enrichmentQueue,
    'ai-analysis': aiAnalysisQueue,
    'notifications': notificationQueue,
    'alerts': alertsQueue,
    'neo4j-sync': neo4jSyncQueue,
    'cve-enrichment': cveEnrichmentQueue,
    'maintenance': maintenanceQueue,
};

// Accepts `string | undefined` so route-param uses (hono ≥4.12 widened
// `c.req.param()` to possibly-undefined) flow through without a `!`. A
// missing/unknown name yields a clean 404 instead of a downstream crash.
function getQueue(name: string | undefined): Queue {
    const queue = name ? queueMap[name] : undefined;
    if (!queue) throw new NotFoundError('Queue', name ?? '<missing>');
    return queue;
}

// ============================================================================
// Bull Board Dashboard
// ============================================================================

const serverAdapter = new HonoAdapter(serveStatic);
serverAdapter.setBasePath('/admin/queues');

createBullBoard({
    queues: allQueues.map(q => new BullMQAdapter(q)),
    serverAdapter,
});

// Mount Bull Board UI
router.route('/queues', serverAdapter.registerPlugin());

// ============================================================================
// Queue Stats API
// ============================================================================

router.get('/stats', requireAuth, async (c) => {
    const stats = await getQueueStats();

    // Include isPaused status for each queue
    const enriched = await Promise.all(
        stats.map(async (s) => {
            const queue = queueMap[s.name];
            const isPaused = queue ? await queue.isPaused() : false;
            return { ...s, isPaused };
        })
    );

    return c.json({
        success: true,
        data: {
            queues: enriched,
            timestamp: new Date().toISOString(),
        },
    });
});

// ============================================================================
// Queue CRUD Operations
// ============================================================================

/** POST /queue/:name/pause — Pause a queue */
router.post('/queue/:name/pause', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    await queue.pause();
    return c.json({ success: true, data: { queue: queue.name, status: 'paused' } });
});

/** POST /queue/:name/resume — Resume a paused queue */
router.post('/queue/:name/resume', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    await queue.resume();
    return c.json({ success: true, data: { queue: queue.name, status: 'resumed' } });
});

/** POST /queue/:name/drain — Remove all waiting jobs */
router.post('/queue/:name/drain', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    await queue.drain();
    return c.json({ success: true, data: { queue: queue.name, action: 'drained' } });
});

/** POST /queue/:name/clean/:state — Clean old jobs by state */
router.post('/queue/:name/clean/:state', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    const state = c.req.param('state') as 'completed' | 'failed' | 'delayed' | 'wait' | 'active';
    const { grace, limit } = AdminQueueCleanSchema.parse(c.req.query());

    const removed = await queue.clean(grace, limit, state);

    return c.json({
        success: true,
        data: { queue: queue.name, state, removed: removed.length },
    });
});

/** POST /queue/:name/retry-all — Retry all failed jobs */
router.post('/queue/:name/retry-all', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));

    const failed = await queue.getFailed(0, 500);
    let retried = 0;
    for (const job of failed) {
        try {
            await job.retry();
            retried++;
        } catch {
            // Job may have been removed or is in an invalid state
        }
    }

    return c.json({
        success: true,
        data: { queue: queue.name, retried, totalFailed: failed.length },
    });
});

/** GET /queue/:name/jobs — List jobs by state */
router.get('/queue/:name/jobs', requireAuth, async (c) => {
    const queue = getQueue(c.req.param('name'));
    const { state, start, limit } = AdminQueueJobsSchema.parse(c.req.query());

    let jobs;
    switch (state) {
        case 'waiting': jobs = await queue.getWaiting(start, start + limit - 1); break;
        case 'active': jobs = await queue.getActive(start, start + limit - 1); break;
        case 'completed': jobs = await queue.getCompleted(start, start + limit - 1); break;
        case 'failed': jobs = await queue.getFailed(start, start + limit - 1); break;
        case 'delayed': jobs = await queue.getDelayed(start, start + limit - 1); break;
        default: jobs = await queue.getFailed(start, start + limit - 1);
    }

    const mapped = jobs.map(job => ({
        id: job.id,
        name: job.name,
        state,
        data: job.data,
        result: job.returnvalue,
        failedReason: job.failedReason || null,
        attemptsMade: job.attemptsMade,
        timestamp: job.timestamp,
        processedOn: job.processedOn || null,
        finishedOn: job.finishedOn || null,
        progress: job.progress,
    }));

    return c.json({
        success: true,
        data: { queue: queue.name, state, start, limit, jobs: mapped },
    });
});

/** DELETE /queue/:name/job/:jobId — Remove a specific job */
router.delete('/queue/:name/job/:jobId', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    const jobId = c.req.param('jobId')!; // route-guaranteed by :jobId pattern

    const job = await queue.getJob(jobId);
    if (!job) throw new NotFoundError('Job', jobId);

    await job.remove();

    return c.json({
        success: true,
        data: { queue: queue.name, jobId, action: 'removed' },
    });
});

/** POST /queue/:name/job/:jobId/retry — Retry a single failed job */
router.post('/queue/:name/job/:jobId/retry', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    const jobId = c.req.param('jobId')!; // route-guaranteed by :jobId pattern

    const job = await queue.getJob(jobId);
    if (!job) throw new NotFoundError('Job', jobId);

    await job.retry();

    return c.json({
        success: true,
        data: { queue: queue.name, jobId, action: 'retried' },
    });
});

/**
 * POST /queue/:name/job/:jobId/promote — Force a delayed job to run now.
 *
 * Calls BullMQ's `job.promote()`, which moves the job from delayed to
 * waiting so the next available worker picks it up immediately. The
 * job's original schedule (if it's a repeatable) is unaffected — only
 * this one delayed instance is promoted.
 */
router.post('/queue/:name/job/:jobId/promote', requireAuth, requireRole('admin'), async (c) => {
    const queue = getQueue(c.req.param('name'));
    const jobId = c.req.param('jobId')!; // route-guaranteed by :jobId pattern

    const job = await queue.getJob(jobId);
    if (!job) throw new NotFoundError('Job', jobId);

    await job.promote();

    return c.json({
        success: true,
        data: { queue: queue.name, jobId, action: 'promoted' },
    });
});

/** GET /queue/:name/job/:jobId — Fetch one job's detail (any queue) */
router.get('/queue/:name/job/:jobId', requireAuth, async (c) => {
    const queue = getQueue(c.req.param('name'));
    const jobId = c.req.param('jobId')!; // route-guaranteed by :jobId pattern

    const job = await queue.getJob(jobId);
    if (!job) throw new NotFoundError('Job', jobId);

    const state = await job.getState();

    return c.json({
        success: true,
        data: {
            id: job.id,
            name: job.name,
            queue: queue.name,
            state,
            progress: job.progress,
            data: job.data,
            result: job.returnvalue,
            failedReason: job.failedReason || null,
            stacktrace: job.stacktrace || null,
            attemptsMade: job.attemptsMade,
            timestamp: job.timestamp,
            processedOn: job.processedOn || null,
            finishedOn: job.finishedOn || null,
        },
    });
});

export default router;
