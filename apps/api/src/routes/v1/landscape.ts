/**
 * Threat Landscape API — Aggregated metrics & trending
 *
 * Dashboard-grade endpoints for threat landscape visualization.
 * Inspired by Recorded Future dashboards and MISP trending.
 *
 * Mounts at: /v1/landscape/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth } from '../../middleware/auth';
import { LandscapeQuerySchema } from '../../lib/schemas';
import { toLandscapeOverview } from '../../dto';

const router = new Hono();
router.use('*', requireAuth);

function periodToInterval(p: string): string {
    return p === '24h' ? '1 day' : p === '7d' ? '7 days' : p === '30d' ? '30 days' : '90 days';
}

// GET /landscape/overview — Full threat landscape snapshot
router.get('/landscape/overview', async (c) => {
    const { period } = LandscapeQuerySchema.parse(c.req.query());
    const interval = periodToInterval(period);

    const [iocStats, vulnStats, iocTypes, topSources, severityDist, notifCount] = await Promise.all([
        rawQuery(sql.raw(`SELECT COUNT(*) AS total, COUNT(CASE WHEN severity = 'critical' THEN 1 END) AS critical, COUNT(CASE WHEN severity = 'high' THEN 1 END) AS high, COALESCE(AVG(risk_score), 0) AS avg_score FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}'`)),
        // severity is stored lowercase (schema: 'none' | 'low' | 'medium' | 'high' | 'critical');
        // the previous uppercase match silently returned 0 for high/critical regardless of data.
        rawQuery(sql.raw(`SELECT COUNT(*) AS total, COUNT(CASE WHEN severity = 'critical' THEN 1 END) AS critical, COUNT(CASE WHEN severity = 'high' THEN 1 END) AS high FROM vulnerabilities WHERE created_at >= NOW() - INTERVAL '${interval}'`)),
        rawQuery(sql.raw(`SELECT type, COUNT(*) AS count FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}' GROUP BY type ORDER BY count DESC LIMIT 10`)),
        rawQuery(sql.raw(`SELECT source, COUNT(*) AS count FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}' GROUP BY source ORDER BY count DESC LIMIT 10`)),
        rawQuery(sql.raw(`SELECT severity, COUNT(*) AS count FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}' GROUP BY severity ORDER BY count DESC`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM notifications WHERE created_at >= NOW() - INTERVAL '${interval}'`)),
    ]);

    return c.json({
        success: true,
        data: toLandscapeOverview({
            period,
            iocStats: iocStats.rows?.[0] as Record<string, unknown> | undefined,
            vulnStats: vulnStats.rows?.[0] as Record<string, unknown> | undefined,
            notifCount: notifCount.rows?.[0] as Record<string, unknown> | undefined,
            iocTypes: (iocTypes.rows ?? []) as Record<string, unknown>[],
            topSources: (topSources.rows ?? []) as Record<string, unknown>[],
            severityDist: (severityDist.rows ?? []) as Record<string, unknown>[],
        }),
    });
});

// GET /landscape/trending — Trending IOCs (new arrivals, sighting spikes)
router.get('/landscape/trending', async (c) => {
    const { period, limit } = LandscapeQuerySchema.parse(c.req.query());
    const interval = periodToInterval(period);

    const [newIOCs, highRisk, recentSightings] = await Promise.all([
        rawQuery(sql.raw(`SELECT value, type, risk_score, source, severity, created_at FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}' ORDER BY created_at DESC LIMIT ${limit}`)),
        rawQuery(sql.raw(`SELECT value, type, risk_score, source, severity FROM iocs WHERE created_at >= NOW() - INTERVAL '${interval}' AND risk_score >= 70 ORDER BY risk_score DESC LIMIT ${limit}`)),
        rawQuery(sql.raw(`SELECT s.ioc_id, i.value, i.type, COUNT(*) AS sighting_count, MAX(s.observed_at) AS latest FROM sightings s JOIN iocs i ON s.ioc_id = i.id WHERE s.observed_at >= NOW() - INTERVAL '${interval}' GROUP BY s.ioc_id, i.value, i.type ORDER BY sighting_count DESC LIMIT ${limit}`)),
    ]);

    return c.json({
        success: true,
        data: {
            period,
            newArrivals: newIOCs.rows || [],
            highRiskIOCs: highRisk.rows || [],
            sightingSpikes: recentSightings.rows || [],
        },
    });
});

// GET /landscape/heatmap — Geographic distribution of threats
router.get('/landscape/heatmap', async (c) => {
    const { period } = LandscapeQuerySchema.parse(c.req.query());
    const interval = periodToInterval(period);

    const result = await rawQuery(sql.raw(`
        SELECT
            raw_data->>'country' AS country,
            raw_data->>'countryCode' AS country_code,
            COUNT(*) AS count,
            COALESCE(AVG(risk_score), 0) AS avg_risk
        FROM iocs
        WHERE created_at >= NOW() - INTERVAL '${interval}'
          AND raw_data->>'country' IS NOT NULL
        GROUP BY raw_data->>'country', raw_data->>'countryCode'
        ORDER BY count DESC
        LIMIT 50
    `));

    return c.json({
        success: true,
        data: {
            period,
            countries: (result.rows || []).map((r: Record<string, unknown>) => ({
                country: r.country, countryCode: r.country_code,
                count: Number(r.count), avgRisk: Math.round(Number(r.avg_risk || 0)),
            })),
        },
    });
});

// GET /landscape/feed-health — Per-feed ingestion health
router.get('/landscape/feed-health', async (c) => {
    const { period } = LandscapeQuerySchema.parse(c.req.query());
    const interval = periodToInterval(period);

    const result = await rawQuery(sql.raw(`
        SELECT
            source,
            COUNT(*) AS iocs_ingested,
            MIN(created_at) AS first_ingestion,
            MAX(created_at) AS last_ingestion,
            COALESCE(AVG(risk_score), 0) AS avg_quality_score,
            COUNT(CASE WHEN severity IN ('critical', 'high') THEN 1 END) AS high_value_iocs
        FROM iocs
        WHERE created_at >= NOW() - INTERVAL '${interval}'
        GROUP BY source
        ORDER BY iocs_ingested DESC
    `));

    return c.json({
        success: true,
        data: {
            period,
            feeds: (result.rows || []).map((r: Record<string, unknown>) => ({
                source: r.source,
                iocsIngested: Number(r.iocs_ingested),
                firstIngestion: r.first_ingestion,
                lastIngestion: r.last_ingestion,
                avgQualityScore: Math.round(Number(r.avg_quality_score || 0)),
                highValueIOCs: Number(r.high_value_iocs),
            })),
        },
    });
});

// GET /landscape/coverage — MITRE ATT&CK technique coverage
router.get('/landscape/coverage', async (c) => {
    const { period } = LandscapeQuerySchema.parse(c.req.query());
    const interval = periodToInterval(period);

    // Count IOCs with MITRE technique tags
    const tagResult = await rawQuery(sql.raw(`
        SELECT unnest(tags) AS tag, COUNT(*) AS count
        FROM iocs
        WHERE created_at >= NOW() - INTERVAL '${interval}'
          AND tags IS NOT NULL
        GROUP BY tag
        ORDER BY count DESC
        LIMIT 100
    `));

    const allTags = (tagResult.rows || []) as Array<Record<string, unknown>>;
    const mitreTechniques = allTags.filter(t => /^T\d{4}/i.test(String(t.tag)));
    const otherTags = allTags.filter(t => !/^T\d{4}/i.test(String(t.tag))).slice(0, 20);

    return c.json({
        success: true,
        data: {
            period,
            mitreTechniques: mitreTechniques.map(t => ({ technique: t.tag, count: Number(t.count) })),
            topTags: otherTags.map(t => ({ tag: t.tag, count: Number(t.count) })),
            totalTechniques: mitreTechniques.length,
        },
    });
});

export default router;
