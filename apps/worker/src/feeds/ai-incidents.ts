/**
 * AI Incident Database — real-world AI harm/failure incidents
 * (https://incidentdatabase.ai)
 *
 * The live "AI threat landscape" signal: ~1500 curated incidents of deployed
 * AI systems causing or nearly causing harm, growing weekly. Complements the
 * static MITRE ATLAS technique taxonomy — ATLAS says *how* AI gets attacked,
 * AID shows *what actually went wrong* in the field, dated.
 *
 * ── Source: the GraphQL API ──
 * AID's GraphQL endpoint gates non-browser callers ("restricted to web
 * browsers"): it requires an `Origin` matching the site plus a browser
 * `User-Agent`. With those two headers a server-side caller is allowed (the
 * data is openly licensed for research/reuse — the gate is anti-abuse, not a
 * licence wall). We page through `incidents(pagination, sort)` and upsert.
 *
 * The API is far richer than the CSV snapshot: the alleged-party relations
 * carry both an `entity_id` slug (clean tags) and a human `name` (display),
 * and reports come with `report_number`s. Lightweight enough to run daily.
 *
 * Sink: the dedicated `ai_incidents` table (NOT atlas_case_studies — see the
 * schema header). Upsert on the natural key `incident_id`.
 */

import { db, sql } from '@rinjani/db';
import { aiIncidents } from '@rinjani/db/schema';
import type { NewAiIncident } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('AIID');

const AIID_GRAPHQL_URL = process.env.AIID_GRAPHQL_URL
    ?? 'https://incidentdatabase.ai/api/graphql';
// The API requires a same-site Origin + a browser UA, or it returns
// "Forbidden — restricted to web browsers". Overridable in case AID changes
// the allowed origin.
const AIID_ORIGIN = process.env.AIID_ORIGIN ?? 'https://incidentdatabase.ai';
const AIID_USER_AGENT = process.env.AIID_USER_AGENT
    ?? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const PAGE_SIZE = 200;
const BATCH_SIZE = 200;

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

interface Entity { entity_id?: string | null; name?: string | null }
interface Report { report_number?: number | null }
interface IncidentNode {
    incident_id: number;
    title?: string | null;
    date?: string | null;
    description?: string | null;
    AllegedDeveloperOfAISystem?: Entity[] | null;
    AllegedDeployerOfAISystem?: Entity[] | null;
    AllegedHarmedOrNearlyHarmedParties?: Entity[] | null;
    reports?: Report[] | null;
}

const INCIDENTS_QUERY = `
query Incidents($limit: Int!, $skip: Int!) {
  incidents(pagination: { limit: $limit, skip: $skip }, sort: { incident_id: ASC }) {
    incident_id
    title
    date
    description
    AllegedDeveloperOfAISystem { entity_id name }
    AllegedDeployerOfAISystem { entity_id name }
    AllegedHarmedOrNearlyHarmedParties { entity_id name }
    reports { report_number }
  }
}`;

async function fetchPage(skip: number): Promise<IncidentNode[]> {
    const res = await fetch(AIID_GRAPHQL_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Origin': AIID_ORIGIN,
            'User-Agent': AIID_USER_AGENT,
        },
        body: JSON.stringify({ query: INCIDENTS_QUERY, variables: { limit: PAGE_SIZE, skip } }),
    });
    if (!res.ok) throw new Error(`GraphQL HTTP ${res.status} ${res.statusText}`);
    const body = await res.json() as { data?: { incidents?: IncidentNode[] }; errors?: Array<{ message: string }> };
    if (body.errors?.length) throw new Error(`GraphQL error: ${body.errors[0].message}`);
    return body.data?.incidents ?? [];
}

/** Page through every incident (sorted ascending) until a short page ends it. */
async function fetchAllIncidents(): Promise<IncidentNode[]> {
    const all: IncidentNode[] = [];
    for (let skip = 0; ; skip += PAGE_SIZE) {
        const page = await fetchPage(skip);
        all.push(...page);
        if (page.length < PAGE_SIZE) break;
        if (skip > 100_000) break; // hard safety cap; the corpus is ~1.5k
    }
    return all;
}

const names = (es: Entity[] | null | undefined): string[] =>
    (es ?? []).map((e) => (e.name ?? '').trim()).filter(Boolean);
const slugs = (es: Entity[] | null | undefined): string[] =>
    (es ?? []).map((e) => (e.entity_id ?? '').trim()).filter(Boolean);

export async function syncAIIncidents(): Promise<SyncResult> {
    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    let nodes: IncidentNode[];
    try {
        nodes = await fetchAllIncidents();
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.error('GraphQL fetch failed', err as Error);
        result.errors.push(`Fetch error: ${msg}`);
        result.failed = 1;
        return result;
    }
    log.info('Fetched AI incidents', { count: nodes.length });

    const mapped: NewAiIncident[] = [];
    for (const n of nodes) {
        const incidentId = Number(n.incident_id);
        if (!Number.isInteger(incidentId)) continue;
        const title = (n.title ?? '').trim();
        if (!title) continue;

        const developers = names(n.AllegedDeveloperOfAISystem);
        const deployers = names(n.AllegedDeployerOfAISystem);
        const harmedParties = names(n.AllegedHarmedOrNearlyHarmedParties);
        const reportIds = (n.reports ?? [])
            .map((r) => Number(r.report_number))
            .filter((x) => Number.isFinite(x));
        const incidentDate = /^\d{4}-\d{2}-\d{2}$/.test((n.date ?? '').trim())
            ? (n.date as string).trim()
            : null;

        // Tags drive the AI-vertical movers signal — use the clean entity_id
        // slugs (developers + deployers), always prefixed with `ai-incident`.
        const tagSlugs = [...new Set([
            ...slugs(n.AllegedDeveloperOfAISystem),
            ...slugs(n.AllegedDeployerOfAISystem),
        ])];

        mapped.push({
            incidentId,
            title,
            description: (n.description ?? '').trim() || null,
            incidentDate,
            deployers,
            developers,
            harmedParties,
            reportIds,
            reportCount: reportIds.length,
            tags: ['ai-incident', ...tagSlugs],
            url: `https://incidentdatabase.ai/cite/${incidentId}`,
            source: 'aiid',
        });
    }

    for (let i = 0; i < mapped.length; i += BATCH_SIZE) {
        const slice = mapped.slice(i, i + BATCH_SIZE);
        try {
            await writeBatch(slice);
            result.processed += slice.length;
        } catch (err) {
            result.failed += slice.length;
            const msg = err instanceof Error ? err.message : String(err);
            if (result.errors.length < 10) result.errors.push(`Batch upsert failed: ${msg}`);
            log.error('Batch upsert error', err as Error);
        }
    }

    log.info('Sync completed', { processed: result.processed, failed: result.failed });
    return result;
}

async function writeBatch(batch: NewAiIncident[]): Promise<void> {
    const now = new Date();
    await db.insert(aiIncidents)
        .values(batch)
        .onConflictDoUpdate({
            target: aiIncidents.incidentId,
            set: {
                title: sql`excluded.title`,
                description: sql`excluded.description`,
                incidentDate: sql`excluded.incident_date`,
                deployers: sql`excluded.deployers`,
                developers: sql`excluded.developers`,
                harmedParties: sql`excluded.harmed_parties`,
                reportIds: sql`excluded.report_ids`,
                reportCount: sql`excluded.report_count`,
                tags: sql`excluded.tags`,
                url: sql`excluded.url`,
                updatedAt: now,
            },
        });
}

/** Standalone runner — `tsx apps/worker/src/feeds/ai-incidents.ts`. */
export async function runAIIncidentsSync(): Promise<void> {
    log.info('Starting full sync');
    try {
        const result = await syncAIIncidents();
        log.info('Full sync completed', { processed: result.processed, failed: result.failed });
    } catch (error) {
        log.error('Sync failed', error as Error);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runAIIncidentsSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
