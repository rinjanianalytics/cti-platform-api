/**
 * Stats & Monitoring Routes
 *
 * Extracted from v1.ts — aggregated counts, distribution, heatmap,
 * tactics, and feed/system health monitoring.
 */

import { Hono } from 'hono';
import { count, db, desc, sql, rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { pulses, indicators, syncLogs, threatActors } from '@rinjani/db/schema';
import * as opensearch from '../../services/opensearch';
import { DaysQuerySchema } from '../../lib/schemas';

const router = new Hono();

// ============================================================================
// Stats
// ============================================================================

router.get('/stats', async (c) => {
    // Batch all independent queries in parallel
    const [counts, [pulseCount], [indicatorCount], recentSyncs] = await Promise.all([
        opensearch.getCounts(),
        db.select({ count: count() }).from(pulses),
        db.select({ count: count() }).from(indicators),
        db.select().from(syncLogs).orderBy(desc(syncLogs.completedAt)).limit(5),
    ]);

    return c.json({
        success: true,
        data: {
            counts: {
                vulnerabilities: counts.vulnerabilities,
                iocs: counts.iocs,
                pulses: pulseCount.count,
                threatActors: counts.actors,
                indicators: indicatorCount.count,
            },
            recentSyncs,
        },
    });
});

/**
 * GET /v1/stats/distribution
 * Get IOC distribution by type
 */
router.get('/stats/distribution', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const distribution = await opensearch.getIOCDistribution(days);
    return c.json({ success: true, data: distribution });
});

/**
 * GET /v1/stats/severity-trend
 * Get severity distribution over time (last 30 days)
 */
router.get('/stats/severity-trend', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const data = await opensearch.getDateHistogram(days);
    return c.json({ success: true, data });
});

/**
 * GET /v1/stats/source-breakdown
 * Get IOC count by source
 */
router.get('/stats/source-breakdown', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const breakdown = await opensearch.getSourceBreakdown(days);
    return c.json({ success: true, data: breakdown });
});

/**
 * GET /v1/stats/threat-heatmap
 * Get IOC distribution by type and severity
 */
router.get('/stats/threat-heatmap', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const heatmapData = await opensearch.getThreatHeatmap(days);
    return c.json({ success: true, data: heatmapData });
});

// ============================================================================
// MITRE ATT&CK - Tactics
// ============================================================================

router.get('/tactics', async (c) => {
    const items = await db.execute(sql`SELECT * FROM tactics ORDER BY mitre_id`) as unknown as Record<string, unknown>[];
    return c.json({
        success: true,
        data: { items, total: items.length },
    });
});

// ============================================================================
// Monitoring & Alerting
// ============================================================================

/**
 * GET /v1/monitoring/feeds
 * Get health status for all feeds
 */
router.get('/monitoring/feeds', async (c) => {
    // Use DISTINCT ON to get only the latest sync per entity_type directly in SQL
    const latestSyncs = await db.execute(sql`
        SELECT DISTINCT ON (entity_type)
            entity_type,
            status,
            items_processed,
            items_failed,
            error_message,
            started_at,
            completed_at,
            EXTRACT(EPOCH FROM (completed_at - started_at)) as duration
        FROM sync_logs
        ORDER BY entity_type, created_at DESC
    `) as unknown as RawQueryResult;

    const feeds = (Array.isArray(latestSyncs) ? latestSyncs : latestSyncs.rows || []).map((sync: Record<string, unknown>) => {
        const itemsProcessed = Number(sync.items_processed || 0);
        const itemsFailed = Number(sync.items_failed || 0);
        const successRate = itemsProcessed + itemsFailed > 0
            ? (itemsProcessed / (itemsProcessed + itemsFailed)) * 100
            : 0;

        let health = 'healthy';
        if (sync.status === 'error') health = 'critical';
        else if (sync.status === 'partial') health = 'warning';
        else if (successRate < 90) health = 'warning';

        return {
            feed: sync.entity_type,
            health,
            status: sync.status,
            lastSync: sync.completed_at,
            itemsProcessed,
            itemsFailed,
            successRate: Math.round(successRate),
            duration: Math.round(Number(sync.duration) || 0),
            errorMessage: sync.error_message,
        };
    });

    return c.json({
        success: true,
        data: {
            feeds,
            summary: {
                total: feeds.length,
                healthy: feeds.filter((f: { health: string }) => f.health === 'healthy').length,
                warning: feeds.filter((f: { health: string }) => f.health === 'warning').length,
                critical: feeds.filter((f: { health: string }) => f.health === 'critical').length,
            },
        },
    });
});

/**
 * GET /v1/monitoring/health
 * Get overall system health
 */
router.get('/monitoring/health', async (c) => {
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);

    const recentSyncs = await db
        .select({ status: syncLogs.status })
        .from(syncLogs)
        .where(sql`${syncLogs.createdAt} >= ${oneDayAgo.toISOString()}`);

    const totalSyncs = recentSyncs.length;
    const failedSyncs = recentSyncs.filter(s => s.status === 'error').length;
    const partialSyncs = recentSyncs.filter(s => s.status === 'partial').length;

    let overallHealth = 'healthy';
    const failureRate = totalSyncs > 0 ? (failedSyncs / totalSyncs) * 100 : 0;

    if (failureRate > 20) overallHealth = 'critical';
    else if (failureRate > 10 || partialSyncs > 5) overallHealth = 'degraded';

    return c.json({
        success: true,
        data: {
            status: overallHealth,
            syncs: {
                total: totalSyncs,
                successful: totalSyncs - failedSyncs - partialSyncs,
                partial: partialSyncs,
                failed: failedSyncs,
            },
            timestamp: new Date().toISOString(),
        },
    });
});

/**
 * GET /v1/stats/freshness
 * Get per-category latest record timestamp and per-feed last sync info.
 * Powers the "Data as of" freshness banners in explorer pages.
 */
router.get('/stats/freshness', async (c) => {
    const [iocFreshness, vulnFreshness, actorFreshness, actorCount, feedSyncs] = await Promise.all([
        opensearch.unifiedSearch({
            query: '', filters: { entityType: ['ioc'] },
            sort: { field: 'updatedAt', order: 'desc' },
            pagination: { page: 1, limit: 1 }, aggregations: false,
        }),
        opensearch.unifiedSearch({
            query: '', filters: { entityType: ['vulnerability'] },
            sort: { field: 'updatedAt', order: 'desc' },
            pagination: { page: 1, limit: 1 }, aggregations: false,
        }),
        db.select({ updatedAt: threatActors.updatedAt })
            .from(threatActors)
            .orderBy(desc(threatActors.updatedAt))
            .limit(1),
        db.select({ count: count() }).from(threatActors),
        db.execute(sql`
            SELECT DISTINCT ON (entity_type)
                entity_type, completed_at, status
            FROM sync_logs
            ORDER BY entity_type, created_at DESC
        `) as unknown as RawQueryResult,
    ]);

    const feedRows = Array.isArray(feedSyncs) ? feedSyncs : feedSyncs.rows || [];

    return c.json({
        success: true,
        data: {
            categories: {
                iocs: { latestRecord: iocFreshness.items[0]?.updatedAt || null, total: iocFreshness.total },
                vulnerabilities: { latestRecord: vulnFreshness.items[0]?.updatedAt || null, total: vulnFreshness.total },
                actors: { latestRecord: actorFreshness[0]?.updatedAt || null, total: actorCount[0]?.count ?? 0 },
            },
            feeds: feedRows.map((f: Record<string, unknown>) => ({
                feed: f.entity_type,
                lastSync: f.completed_at,
                status: f.status,
            })),
            timestamp: new Date().toISOString(),
        },
    });
});

/**
 * GET /v1/stats/trending-tags
 * Top IOC tags from the last 30 days — powers the "Trending Now" search sidebar.
 */
router.get('/stats/trending-tags', async (c) => {
    const limit = Math.min(Number(c.req.query('limit') || '8'), 20);
    const rows = await db.execute(sql`
        SELECT tag, cnt FROM (
            SELECT unnest(tags) as tag, count(*) as cnt
            FROM iocs
            WHERE tags IS NOT NULL AND array_length(tags,1) > 0
              AND created_at > NOW() - INTERVAL '30 days'
            GROUP BY tag
        ) sub
        WHERE tag <> '' AND length(tag) > 1
        ORDER BY cnt DESC
        LIMIT ${limit}
    `) as unknown as Array<{ tag: string; cnt: number }>;

    // A tag is "hot" if it has notable absolute volume AND sits within 70% of
    // the leader's count. Adapts to the dataset — flat distributions surface
    // multiple hot tags, dominant leaders mark only the spike. During low-
    // volume windows nothing is hot (which is honest).
    const counts = (Array.isArray(rows) ? rows : []).map(r => Number(r.cnt));
    const top = counts[0] ?? 0;
    const HOT_MIN_ABS = 100;
    const HOT_REL_THRESHOLD = 0.7;
    const hotFloor = Math.max(HOT_MIN_ABS, top * HOT_REL_THRESHOLD);

    const tags = (Array.isArray(rows) ? rows : []).map((r) => {
        const count = Number(r.cnt);
        return {
            tag: String(r.tag),
            count,
            hot: count >= hotFloor,
        };
    });

    return c.json({ success: true, data: tags });
});

export default router;
