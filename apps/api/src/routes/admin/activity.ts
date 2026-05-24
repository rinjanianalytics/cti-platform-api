/**
 * Admin: BullMQ job activity feed.
 *
 *   GET /admin/activity/recent      → rolling buffer of last events
 *   GET /admin/activity/throughput  → per-queue counters
 *   GET /admin/activity/stream      → SSE live stream of new events
 *
 * The data lives in `services/jobActivityStream.ts`, which subscribes to
 * QueueEvents on module import and keeps an in-memory ring buffer.
 */

import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming';
import { requireAuth, requireRole } from '../../middleware/auth';
import {
    getRecentActivity,
    getThroughputStats,
    getFailureGroups,
    subscribeLive,
} from '../../services/jobActivityStream';

const router = new Hono();

/** GET /admin/activity/recent — newest-first slice of the ring buffer. */
router.get('/activity/recent', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    const q = c.req.query();
    const limit = Number(q.limit) || 50;
    const queue = q.queue || undefined;
    const sinceSeq = q.sinceSeq ? Number(q.sinceSeq) : undefined;

    const events = getRecentActivity({ limit, queue, sinceSeq });
    return c.json({ success: true, data: { events, count: events.length } });
});

/** GET /admin/activity/throughput — per-queue counters over the buffer window. */
router.get('/activity/throughput', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    return c.json({ success: true, data: { queues: getThroughputStats() } });
});

/**
 * GET /admin/activity/failures — failed events grouped by normalised signature.
 *
 * Same buffer window as `/recent`. Group counts collapse "same error,
 * different details" so a rate-limit storm shows as one row, not 50.
 */
router.get('/activity/failures', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    return c.json({ success: true, data: { groups: getFailureGroups() } });
});

/**
 * GET /admin/activity/stream — SSE live stream of all activity events.
 *
 * Auth via `?api_key=…` query because EventSource can't set headers; the
 * global optionalAuth middleware accepts that. `requireAuth` ensures a
 * user resolved before the stream opens.
 */
router.get('/activity/stream', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    return streamSSE(c, async (stream) => {
        // Send hello + recent backfill so the client renders immediately.
        await stream.writeSSE({
            event: 'connected',
            data: JSON.stringify({ ts: new Date().toISOString() }),
        });

        for (const evt of getRecentActivity({ limit: 25 }).reverse()) {
            await stream.writeSSE({
                event: 'activity',
                data: JSON.stringify(evt),
            });
        }

        const unsubscribe = subscribeLive(async (evt) => {
            try {
                await stream.writeSSE({
                    event: 'activity',
                    data: JSON.stringify(evt),
                });
            } catch {
                // Stream is closed — cleanup below will fire.
            }
        });

        const heartbeat = setInterval(async () => {
            try {
                await stream.writeSSE({
                    event: 'heartbeat',
                    data: JSON.stringify({ ts: new Date().toISOString() }),
                });
            } catch {
                clearInterval(heartbeat);
            }
        }, 30_000);

        stream.onAbort(() => {
            unsubscribe();
            clearInterval(heartbeat);
        });

        // Keep the stream open until aborted.
        await new Promise(() => { });
    });
});

export default router;
