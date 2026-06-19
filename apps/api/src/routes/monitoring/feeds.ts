/**
 * Monitoring — Feed Health Routes
 *
 * Reads from `feed_sync_runs` — the authoritative per-feed run log written by the
 * feed-sync worker (`beginFeedSyncRun(source)`) for EVERY scheduled feed, keyed
 * by `feed_id` (= the feed source). The legacy `sync_logs` table only ever
 * covered the original feeds, so scheduler-driven feeds (aiid, ofac, scamsniffer,
 * defillama, …) were invisible here even though they run — they now appear.
 */

import { Hono } from 'hono';
import { db, sql, desc, eq } from '@rinjani/db';
import { feedSyncRuns } from '@rinjani/db/schema';
import { NotFoundError } from '../../lib/errors';

const feedRoutes = new Hono();

/** Drizzle's execute() may return `{ rows }` or the array directly by driver. */
function extractRows(result: unknown): Record<string, unknown>[] {
    if (Array.isArray(result)) return result as Record<string, unknown>[];
    if (result && typeof result === 'object' && 'rows' in result) {
        return (result as { rows: Record<string, unknown>[] }).rows ?? [];
    }
    return [];
}

function deriveHealth(status: string, processed: number, failed: number): 'healthy' | 'warning' | 'critical' {
    if (status === 'failed') return 'critical';
    if (status === 'running') return 'healthy';            // in-progress
    const total = processed + failed;
    if (failed > 0 && total > 0 && processed / total < 0.9) return 'warning';
    return 'healthy';
}

/**
 * GET /v1/monitoring/feeds
 * Health status for every feed — the latest run per feed.
 */
feedRoutes.get('/feeds', async (c) => {
    // Latest run per feed. DISTINCT ON keeps this correct regardless of how
    // noisy any one feed is (a rare weekly feed's last run can't be pushed out
    // of a fixed window). `all` is the fan-out parent, not a feed — skip it.
    const result = await db.execute(sql`
        SELECT DISTINCT ON (feed_id)
            feed_id, status, items_ingested, errors, error_details,
            started_at, completed_at, duration_ms
        FROM feed_sync_runs
        WHERE feed_id <> 'all'
        ORDER BY feed_id, started_at DESC
    `);

    const feeds = extractRows(result).map((r) => {
        const processed = Number(r.items_ingested ?? 0);
        const failed = Number(r.errors ?? 0);
        const total = processed + failed;
        const status = String(r.status ?? 'unknown');
        const successRate = total > 0 ? (processed / total) * 100 : status === 'completed' ? 100 : 0;
        return {
            feed: String(r.feed_id),
            health: deriveHealth(status, processed, failed),
            status,
            lastSync: (r.completed_at ?? r.started_at) as string | null,
            itemsProcessed: processed,
            itemsFailed: failed,
            successRate: Math.round(successRate),
            duration: Math.round(Number(r.duration_ms ?? 0) / 1000),
            errorMessage: (r.error_details ?? null) as string | null,
        };
    }).sort((a, b) => a.feed.localeCompare(b.feed));

    return c.json({
        success: true,
        data: {
            feeds,
            summary: {
                total: feeds.length,
                healthy: feeds.filter((f) => f.health === 'healthy').length,
                warning: feeds.filter((f) => f.health === 'warning').length,
                critical: feeds.filter((f) => f.health === 'critical').length,
            },
        },
    });
});

/**
 * GET /v1/monitoring/feeds/:feedId
 * Last 10 runs for a specific feed.
 */
feedRoutes.get('/feeds/:feedId', async (c) => {
    const feedId = c.req.param('feedId');

    const runs = await db
        .select({
            id: feedSyncRuns.id,
            status: feedSyncRuns.status,
            itemsIngested: feedSyncRuns.itemsIngested,
            errors: feedSyncRuns.errors,
            errorDetails: feedSyncRuns.errorDetails,
            startedAt: feedSyncRuns.startedAt,
            completedAt: feedSyncRuns.completedAt,
            durationMs: feedSyncRuns.durationMs,
        })
        .from(feedSyncRuns)
        .where(eq(feedSyncRuns.feedId, feedId))
        .orderBy(desc(feedSyncRuns.startedAt))
        .limit(10);

    if (runs.length === 0) {
        throw new NotFoundError('Feed', feedId);
    }

    const latest = runs[0];
    const processed = latest.itemsIngested ?? 0;
    const failed = latest.errors ?? 0;
    const total = processed + failed;
    const successRate = total > 0 ? (processed / total) * 100 : latest.status === 'completed' ? 100 : 0;

    return c.json({
        success: true,
        data: {
            feed: feedId,
            latest: {
                status: latest.status,
                health: deriveHealth(latest.status, processed, failed),
                lastSync: latest.completedAt ?? latest.startedAt,
                itemsProcessed: processed,
                itemsFailed: failed,
                successRate: Math.round(successRate),
                duration: Math.round((latest.durationMs ?? 0) / 1000),
                errorMessage: latest.errorDetails,
            },
            history: runs.map((s) => ({
                timestamp: s.completedAt ?? s.startedAt,
                status: s.status,
                itemsProcessed: s.itemsIngested ?? 0,
                itemsFailed: s.errors ?? 0,
                duration: Math.round((s.durationMs ?? 0) / 1000),
            })),
        },
    });
});

export default feedRoutes;
