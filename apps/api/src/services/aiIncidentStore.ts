/**
 * AI-incident store — read CRUD for the ai_incidents table (AI vertical).
 *
 * Rows are feed-ingested from the AI Incident Database (see
 * apps/worker/src/feeds/ai-incidents.ts); this is the read side the dashboard
 * + Hunt agent consume. `stats()` powers the "AI incidents over time" trend —
 * the AI-vertical analogue of the IOC landscape-shift band.
 */

import { db, desc, ilike, and, gte, sql } from '@rinjani/db';
import { aiIncidents } from '@rinjani/db/schema';
import type { AiIncident } from '@rinjani/db/schema';

export async function listAiIncidents(filters: {
    q?: string;
    /** Filter to incidents on/after this YYYY-MM-DD. */
    since?: string;
    limit?: number;
    /**
     * 'recency' (default) — order by INGESTION (created_at). incidentdatabase.ai
     * back-dates incidents (a catalog entry added today can describe a years-old
     * event), so an event-date sort buries fresh additions and the feed looks
     * frozen. 'date' — order by the EVENT date (incident_date) for a true
     * timeline reading (most recent incident first). The dashboard offers both
     * as a toggle; `incident_id` is the stable tiebreak.
     */
    sort?: 'recency' | 'date';
} = {}): Promise<AiIncident[]> {
    const conds = [];
    if (filters.q) conds.push(ilike(aiIncidents.title, `%${filters.q}%`));
    if (filters.since && /^\d{4}-\d{2}-\d{2}$/.test(filters.since)) {
        conds.push(gte(aiIncidents.incidentDate, filters.since));
    }
    const orderBy = filters.sort === 'date'
        ? [sql`${aiIncidents.incidentDate} DESC NULLS LAST`, desc(aiIncidents.incidentId)]
        : [desc(aiIncidents.createdAt), desc(aiIncidents.incidentId)];
    return db
        .select()
        .from(aiIncidents)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(...orderBy)
        .limit(Math.min(filters.limit ?? 100, 500));
}

export type TimelineGranularity = 'day' | 'week' | 'month';

export interface AiIncidentStats {
    total: number;
    /** The granularity the timeline buckets reflect (echoed back for the UI). */
    granularity: TimelineGranularity;
    /** Incidents per bucket (the `month` key holds the bucket label regardless
     *  of granularity: YYYY-MM-DD for day/week, YYYY-MM for month). */
    timeline: Array<{ month: string; count: number }>;
    /** Most-named developers across all incidents — the AI-vertical movers. */
    topDevelopers: Array<{ name: string; count: number }>;
}

export async function aiIncidentStats(
    months = 24,
    granularity: TimelineGranularity = 'month',
): Promise<AiIncidentStats> {
    const [{ total }] = await db
        .select({ total: sql<number>`count(*)::int` })
        .from(aiIncidents);

    // Bucket expression + trailing window per granularity. Day/week use fixed
    // windows so the chart stays readable; month honours the `months` param.
    const bucket = granularity === 'day'
        ? sql`to_char(incident_date, 'YYYY-MM-DD')`
        : granularity === 'week'
            ? sql`to_char(date_trunc('week', incident_date), 'YYYY-MM-DD')`
            : sql`to_char(incident_date, 'YYYY-MM')`;
    const windowClause = granularity === 'day'
        ? sql`incident_date >= CURRENT_DATE - INTERVAL '90 days'`
        : granularity === 'week'
            ? sql`incident_date >= CURRENT_DATE - INTERVAL '52 weeks'`
            : sql`incident_date >= (CURRENT_DATE - (${months} || ' months')::interval)`;

    const timelineRows = await db.execute(sql`
        SELECT ${bucket} AS month, count(*)::int AS count
        FROM ai_incidents
        WHERE incident_date IS NOT NULL AND ${windowClause}
        GROUP BY month
        ORDER BY month
    `) as unknown as Array<{ month: string; count: number }>;

    // Top alleged developers (jsonb string[] unnested).
    const devRows = await db.execute(sql`
        SELECT slug AS name, count(*)::int AS count
        FROM ai_incidents, jsonb_array_elements_text(developers) AS slug
        GROUP BY slug
        ORDER BY count DESC
        LIMIT 15
    `) as unknown as Array<{ name: string; count: number }>;

    return {
        total: Number(total) || 0,
        granularity,
        timeline: timelineRows.map((r) => ({ month: r.month, count: Number(r.count) })),
        topDevelopers: devRows.map((r) => ({ name: r.name, count: Number(r.count) })),
    };
}
