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
} = {}): Promise<AiIncident[]> {
    const conds = [];
    if (filters.q) conds.push(ilike(aiIncidents.title, `%${filters.q}%`));
    if (filters.since && /^\d{4}-\d{2}-\d{2}$/.test(filters.since)) {
        conds.push(gte(aiIncidents.incidentDate, filters.since));
    }
    // Order by INGESTION recency, not event date. incidentdatabase.ai publishes
    // back-dated incidents (a catalog entry added today can describe an event
    // from months ago), so an incident-date sort makes the feed look frozen —
    // freshly-ingested incidents sink below an older `incident_date` ceiling.
    // `created_at DESC` surfaces what was actually just pulled; `incident_id` is
    // a stable tiebreak within the bulk-seeded rows (which share a created_at).
    return db
        .select()
        .from(aiIncidents)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(aiIncidents.createdAt), desc(aiIncidents.incidentId))
        .limit(Math.min(filters.limit ?? 100, 500));
}

export interface AiIncidentStats {
    total: number;
    /** Incidents per month (YYYY-MM) over the window — the "over time" trend. */
    timeline: Array<{ month: string; count: number }>;
    /** Most-named developers across all incidents — the AI-vertical movers. */
    topDevelopers: Array<{ name: string; count: number }>;
}

export async function aiIncidentStats(months = 24): Promise<AiIncidentStats> {
    const [{ total }] = await db
        .select({ total: sql<number>`count(*)::int` })
        .from(aiIncidents);

    // Monthly buckets by incident_date over the trailing window.
    const timelineRows = await db.execute(sql`
        SELECT to_char(incident_date, 'YYYY-MM') AS month, count(*)::int AS count
        FROM ai_incidents
        WHERE incident_date >= (CURRENT_DATE - (${months} || ' months')::interval)
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
        timeline: timelineRows.map((r) => ({ month: r.month, count: Number(r.count) })),
        topDevelopers: devRows.map((r) => ({ name: r.name, count: Number(r.count) })),
    };
}
