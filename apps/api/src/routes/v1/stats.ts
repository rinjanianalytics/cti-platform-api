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
// `iocs` / `vulnerabilities` / `feed_sync_runs` are queried via `rawQuery`
// below — Drizzle schema imports aren't needed for the SQL-string path.
import * as opensearch from '../../services/opensearch';
import { DaysQuerySchema } from '../../lib/schemas';
import { computeSignalFunnel } from '../../services/signalFunnel';

const router = new Hono();

// ============================================================================
// Stats
// ============================================================================

router.get('/stats', async (c) => {
    // `?days=N` is optional — when present, the response also includes
    // `windowCounts` (new arrivals within the last N days). `counts`
    // remains total-of-record so older clients keep working unchanged.
    // The command dashboard uses `windowCounts` for the KPI tile values
    // when the user has picked 24H/7D/30D on the rolling-window switch.
    const daysRaw = c.req.query('days');
    const daysParam = daysRaw != null ? Number(daysRaw) : null;
    const days = daysParam != null && Number.isFinite(daysParam) && daysParam > 0
        ? Math.min(Math.floor(daysParam), 365)
        : null;

    const [counts, [pulseCount], [indicatorCount], recentSyncs, windowCounts] = await Promise.all([
        opensearch.getCounts(),
        db.select({ count: count() }).from(pulses),
        db.select({ count: count() }).from(indicators),
        db.select().from(syncLogs).orderBy(desc(syncLogs.completedAt)).limit(5),
        days != null ? getWindowCounts(days) : Promise.resolve(null),
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
            // Only present when `?days=N` is passed. Shape mirrors `counts`
            // so the frontend can swap one for the other without
            // re-mapping fields.
            ...(windowCounts != null && { windowCounts, windowDays: days }),
            recentSyncs,
        },
    });
});

/**
 * Counts of records active within the last N days. Same shape as the
 * `counts` object so the frontend can use either interchangeably.
 *
 *   • iocs/vulnerabilities/pulses/indicators — bucket by `created_at`
 *     (when the row landed in our DB).
 *   • threatActors — distinct actors mentioned in pulses within the
 *     window. `last_seen` mirrors MITRE's upstream `modified` and is
 *     essentially static after import (most actors haven't been
 *     re-touched in months), so filtering by it returns zero across
 *     the board. Pulse-adversary matching is the truthful, live
 *     signal of "active" actors.
 */
async function getWindowCounts(days: number): Promise<{
    vulnerabilities: number;
    iocs: number;
    pulses: number;
    threatActors: number;
    indicators: number;
}> {
    const result = await rawQuery<{
        iocs: number;
        vulnerabilities: number;
        pulses: number;
        threat_actors: number;
        indicators: number;
    }>(sql`
        SELECT
            (SELECT COUNT(*)::int FROM iocs WHERE created_at > now() - (${days}::int * interval '1 day'))            AS iocs,
            (SELECT COUNT(*)::int FROM vulnerabilities WHERE created_at > now() - (${days}::int * interval '1 day')) AS vulnerabilities,
            (SELECT COUNT(*)::int FROM pulses WHERE created_at > now() - (${days}::int * interval '1 day'))          AS pulses,
            (
                SELECT COUNT(DISTINCT t.id)::int
                FROM threat_actors t
                WHERE EXISTS (
                    SELECT 1 FROM pulses p
                    WHERE p.otx_modified > now() - (${days}::int * interval '1 day')
                      AND p.adversary IS NOT NULL AND p.adversary <> ''
                      AND (
                          LOWER(p.adversary) = LOWER(t.name)
                          OR (t.aliases IS NOT NULL AND LOWER(p.adversary) IN (
                              SELECT LOWER(elem::text)
                              FROM jsonb_array_elements_text((t.aliases #>> '{}')::jsonb) AS elem
                          ))
                      )
                )
            ) AS threat_actors,
            (SELECT COUNT(*)::int FROM indicators WHERE created_at > now() - (${days}::int * interval '1 day'))      AS indicators
    `);
    const row = result.rows[0] ?? {
        iocs: 0, vulnerabilities: 0, pulses: 0, threat_actors: 0, indicators: 0,
    };
    return {
        vulnerabilities: Number(row.vulnerabilities),
        iocs: Number(row.iocs),
        pulses: Number(row.pulses),
        threatActors: Number(row.threat_actors),
        indicators: Number(row.indicators),
    };
}

/**
 * GET /v1/stats/sparklines?days=7
 *
 * Daily-bucketed counts for the four overview KPI tiles, so the dashboard
 * can render a Workbench-style mini-trend next to each headline number.
 *
 * Series are zero-filled — a quiet day on a given metric returns `0` for
 * that bucket rather than dropping the index, so frontend sparklines render
 * with a constant array length regardless of activity.
 *
 *   iocs           — new IOCs created per day (iocs.created_at)
 *   vulnerabilities — new vulns created per day (vulnerabilities.created_at)
 *   threatActors   — distinct actors mentioned in OTX pulses per day
 *                    (pulses.adversary matched against actor name/aliases).
 *                    Used to be bucketed by `threat_actors.last_seen` but
 *                    that mirrors MITRE's upstream `modified` and is
 *                    essentially static after import, so the series read
 *                    flat-zero for the user's window. Pulse mentions are
 *                    the truthful, live signal of actor activity.
 *   feedSyncs      — successful feed-sync runs per day (feed_sync_runs.started_at, status='completed')
 *
 * The shape is intentionally small (4 × ~7-30 ints) so this is cheap to
 * fetch alongside the existing /stats call from the overview page.
 */
router.get('/stats/sparklines', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());

    // One SQL trip per metric — cheap (indexed timestamp range + GROUP BY day).
    // Could be Promise.all'd, but the connection pool can serialize them just
    // as fast for under-1ms per query at our row counts.
    const series = await Promise.all([
        bucketDaily('iocs', 'created_at', days),
        bucketDaily('vulnerabilities', 'created_at', days),
        bucketDailyActorMentions(days),
        bucketDailyFeedSyncs(days),
    ]);

    return c.json({
        success: true,
        data: {
            days,
            iocs:            series[0],
            vulnerabilities: series[1],
            threatActors:    series[2],
            feedSyncs:       series[3],
        },
    });
});

/**
 * Generic daily bucketing helper. `table` and `column` are NOT user input —
 * they are hardcoded identifiers from the call sites above. The day series
 * is generated via `generate_series` so missing days return 0 (left-join).
 */
async function bucketDaily(
    table: 'iocs' | 'vulnerabilities',
    column: 'created_at',
    days: number,
): Promise<number[]> {
    const result = await rawQuery(`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - INTERVAL '${days - 1} days',
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(t.${column}), 0)::int AS n
        FROM d
        LEFT JOIN ${table} t
            ON date_trunc('day', t.${column}) = d.day
        GROUP BY d.day
        ORDER BY d.day ASC
    `) as RawQueryResult<{ day: string; n: number }>;
    return result.rows.map(r => Number(r.n));
}

/**
 * Distinct threat actors mentioned in OTX pulses per day. The match is
 * case-insensitive against the actor's name OR any alias. `aliases` is
 * stored as a JSONB-string-containing-JSON (double-encoded); `#>> '{}'`
 * unwraps the outer string layer, then we re-cast and iterate via
 * jsonb_array_elements_text. Same pattern as /v1/actors/active.
 *
 * COUNT(DISTINCT t.id) per day so a single popular actor mentioned in
 * 30 pulses doesn't inflate the count — what matters is "how many
 * different actors had observable activity each day".
 */
async function bucketDailyActorMentions(days: number): Promise<number[]> {
    const result = await rawQuery(`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - INTERVAL '${days - 1} days',
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(DISTINCT m.actor_id), 0)::int AS n
        FROM d
        LEFT JOIN (
            SELECT
                t.id AS actor_id,
                date_trunc('day', p.otx_modified)::date AS day
            FROM threat_actors t
            JOIN pulses p ON (
                p.adversary IS NOT NULL AND p.adversary <> ''
                AND (
                    LOWER(p.adversary) = LOWER(t.name)
                    OR (t.aliases IS NOT NULL AND LOWER(p.adversary) IN (
                        SELECT LOWER(elem::text)
                        FROM jsonb_array_elements_text((t.aliases #>> '{}')::jsonb) AS elem
                    ))
                )
            )
            WHERE p.otx_modified > date_trunc('day', NOW()) - INTERVAL '${days - 1} days'
        ) m ON m.day = d.day
        GROUP BY d.day
        ORDER BY d.day ASC
    `) as RawQueryResult<{ day: string; n: number }>;
    return result.rows.map(r => Number(r.n));
}

/**
 * `feed_sync_runs` has a different shape — bucketing by `started_at` and
 * filtering by `status='completed'` so we count successful sync runs, not
 * failed ones. The latter are visible on /admin/services.
 */
async function bucketDailyFeedSyncs(days: number): Promise<number[]> {
    const result = await rawQuery(`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - INTERVAL '${days - 1} days',
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(r.started_at) FILTER (WHERE r.status = 'completed'), 0)::int AS n
        FROM d
        LEFT JOIN feed_sync_runs r
            ON date_trunc('day', r.started_at) = d.day
        GROUP BY d.day
        ORDER BY d.day ASC
    `) as RawQueryResult<{ day: string; n: number }>;
    return result.rows.map(r => Number(r.n));
}

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
 * GET /v1/stats/funnel
 * The signal funnel in one query: ingested → indicators → correlated →
 * validated → actioned (the last from siem_export_logs pushes).
 */
router.get('/stats/funnel', async (c) => {
    const data = await computeSignalFunnel();
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
    // Latest run per feed from `feed_sync_runs` — the authoritative per-feed log
    // the feed-sync worker writes for EVERY scheduled feed (keyed by feed_id =
    // source). The legacy `sync_logs` table only covered the original feeds, so
    // scheduler-driven feeds (aiid, ofac, scamsniffer, defillama, …) were
    // invisible here even though they run. `all` is the fan-out parent — skip it.
    const latestRuns = await db.execute(sql`
        SELECT DISTINCT ON (feed_id)
            feed_id,
            status,
            items_ingested,
            errors,
            error_details,
            started_at,
            completed_at,
            (duration_ms / 1000.0) as duration
        FROM feed_sync_runs
        WHERE feed_id <> 'all'
        ORDER BY feed_id, started_at DESC
    `) as unknown as RawQueryResult;

    const feeds = (Array.isArray(latestRuns) ? latestRuns : latestRuns.rows || []).map((run: Record<string, unknown>) => {
        const itemsProcessed = Number(run.items_ingested || 0);
        const itemsFailed = Number(run.errors || 0);
        const status = String(run.status || 'unknown');
        const total = itemsProcessed + itemsFailed;
        const successRate = total > 0 ? (itemsProcessed / total) * 100 : status === 'completed' ? 100 : 0;

        let health = 'healthy';
        if (status === 'failed') health = 'critical';
        else if (status === 'running') health = 'healthy';
        else if (itemsFailed > 0 && successRate < 90) health = 'warning';

        return {
            feed: run.feed_id,
            health,
            status,
            lastSync: run.completed_at ?? run.started_at,
            itemsProcessed,
            itemsFailed,
            successRate: Math.round(successRate),
            duration: Math.round(Number(run.duration) || 0),
            errorMessage: run.error_details,
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
 * GET /v1/stats/trending-tags?days=30&limit=8
 *           …or              ?hours=6&limit=8
 *
 * Top IOC tags from the last N days/hours. Powers the "Trending Now"
 * search sidebar, the command page's trending panel, and the feeds
 * page's Landscape-shift band (6H / 24H / 7D segmented control).
 *
 * `hours` wins over `days` when both are present so sub-day windows
 * (the 6H / 24H toggles) can be expressed without losing the integer-
 * day path for the 30-day default. Internally we collapse to a minutes
 * value so both paths share one SQL.
 *
 * Defaults: `days=30` (the original hardcoded window) so older clients
 * see no behaviour change.
 */
router.get('/stats/trending-tags', async (c) => {
    const limit = Math.min(Number(c.req.query('limit') || '8'), 20);
    const hoursParam = c.req.query('hours');
    let totalMinutes: number;
    if (hoursParam != null && hoursParam !== '') {
        const hours = Math.max(1, Math.min(Math.floor(Number(hoursParam)) || 24, 24 * 365));
        totalMinutes = hours * 60;
    } else {
        const daysRaw = Number(c.req.query('days') || '30');
        const days = Math.max(1, Math.min(Math.floor(daysRaw) || 30, 365));
        totalMinutes = days * 24 * 60;
    }
    const rows = await db.execute(sql`
        SELECT tag, cnt FROM (
            SELECT unnest(tags) as tag, count(*) as cnt
            FROM iocs
            WHERE tags IS NOT NULL AND array_length(tags,1) > 0
              AND created_at > now() - (${totalMinutes}::int * interval '1 minute')
              -- Trending is a "what's hot RIGHT NOW" surface, so decayed
              -- IOCs (iocs.decayed_at IS NOT NULL — see PR #105's marker
              -- layer) are excluded. The OpenSearch-backed /stats/*
              -- endpoints get this filtering for free via the prune job
              -- (PR #106); this query hits Postgres directly so it
              -- needs the clause explicitly.
              AND decayed_at IS NULL
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
