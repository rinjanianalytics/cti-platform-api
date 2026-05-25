/**
 * Threats Routes (Pulses, Threat Actors, Indicators)
 *
 * Extracted from v1.ts — list and detail endpoints for threat entities.
 */

import { Hono } from 'hono';
import { db } from '@rinjani/db';
import { and, count, desc, eq, ilike, or, sql, type SQL } from '@rinjani/db';
import { rawQuery } from '@rinjani/db';
import { pulses, threatActors, indicators } from '@rinjani/db/schema';
import { iocs } from '@rinjani/db/schema';
import { NotFoundError } from '../../lib/errors';
import { PaginationSchema, ThreatActorFilterSchema } from '../../lib/schemas';
import { paginate } from './helpers';
import { parseCursorParams, buildCursorResponse } from '../../lib/pagination';
import { escSql } from '../../lib/sanitize';

const router = new Hono();

// ============================================================================
// Pulses (AlienVault OTX)
// ============================================================================

router.get('/pulses', async (c) => {
    const { page, pageSize } = PaginationSchema.parse(c.req.query());

    const items = await db.select()
        .from(pulses)
        .orderBy(desc(pulses.otxModified))
        .limit(pageSize)
        .offset((page - 1) * pageSize);

    const [{ total }] = await db.select({ total: count() }).from(pulses);

    return c.json({
        success: true,
        data: {
            items,
            pagination: paginate(page, pageSize, total),
        },
    });
});

// ============================================================================
// Single Pulse Detail
// ============================================================================

router.get('/pulses/:id', async (c) => {
    const { id } = c.req.param();

    // Lookup by UUID or OTX ID
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    const whereClause = isUUID
        ? eq(pulses.id, id)
        : eq(pulses.otxId, id);

    const [pulse] = await db.select().from(pulses).where(whereClause).limit(1);

    if (!pulse) {
        throw new NotFoundError('Pulse', id);
    }

    // Fetch related IOCs linked to this pulse
    const relatedIOCs = await db.select()
        .from(iocs)
        .where(eq(iocs.pulseId, pulse.otxId))
        .limit(100);

    return c.json({
        success: true,
        data: { ...pulse, relatedIOCs },
    });
});

// ============================================================================
// Pulses — Cursor Pagination (PostgreSQL direct)
// ============================================================================

router.get('/pulses/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    let whereClause = '';
    if (cursor) {
        const op = direction === 'next' ? '<' : '>';
        whereClause = `WHERE (otx_modified, id::text) ${op} ('${escSql(cursor.timestamp)}', '${escSql(cursor.id)}')`;
    }

    const orderDir = direction === 'next' ? 'DESC' : 'ASC';

    const result = await rawQuery(
        `SELECT * FROM pulses ${whereClause}
         ORDER BY otx_modified ${orderDir} NULLS LAST, id ${orderDir}
         LIMIT ${limit + 1}`
    );

    const rows = result.rows || [];
    if (direction === 'prev') rows.reverse();

    const response = buildCursorResponse(rows, limit, (row: Record<string, unknown>) => ({
        timestamp: String(row.otx_modified || row.created_at || ''),
        id: String(row.id || ''),
    }));

    return c.json({ success: true, ...response });
});

// ============================================================================
// Threat Actors
// ============================================================================

router.get('/threats', async (c) => {
    const { page, pageSize, q, sophistication, motivation } = ThreatActorFilterSchema.parse(c.req.query());

    // Build server-side WHERE conditions
    const conditions: SQL[] = [];
    if (q) {
        const searchCondition = or(
            ilike(threatActors.name, `%${q}%`),
            ilike(threatActors.description, `%${q}%`),
        );
        if (searchCondition) conditions.push(searchCondition);
    }
    if (sophistication) conditions.push(eq(threatActors.sophistication, sophistication));
    if (motivation) conditions.push(eq(threatActors.primaryMotivation, motivation));

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    // Order by upstream `last_seen` (when activity was actually observed)
    // with a fallback to `updated_at` for actors that have no `last_seen`
    // recorded — keeps freshly-synced metadata-only records from sinking to
    // the bottom while still surfacing genuinely-active actors first.
    const items = await db.select()
        .from(threatActors)
        .where(whereClause)
        .orderBy(sql`COALESCE(${threatActors.lastSeen}, ${threatActors.updatedAt}) DESC NULLS LAST`)
        .limit(pageSize)
        .offset((page - 1) * pageSize);

    const countQuery = db.select({ total: count() }).from(threatActors);
    if (whereClause) countQuery.where(whereClause);
    const [{ total }] = await countQuery;

    return c.json({
        success: true,
        data: {
            items,
            pagination: paginate(page, pageSize, total),
        },
    });
});

router.get('/threats/:id', async (c) => {
    const { id } = c.req.param();

    // Determine lookup strategy: UUID → id column, STIX-like → stixId, else → name
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    const isStixLike = id.includes('--');

    const whereClause = isUUID
        ? eq(threatActors.id, id)
        : isStixLike
            ? eq(threatActors.stixId, id)
            : eq(threatActors.name, decodeURIComponent(id));

    // Fetch actor directly from PostgreSQL (which has complete data)
    const [actor] = await db
        .select()
        .from(threatActors)
        .where(whereClause)
        .limit(1);

    if (!actor) {
        throw new NotFoundError('Threat actor', id);
    }

    // Find all actors with matching name to merge intelligence
    const allMatchingActors = await db
        .select()
        .from(threatActors)
        .where(eq(threatActors.name, actor.name));

    const mergedActor = { ...actor };

    // Merge missing scalar fields
    const strFields = ['sophistication', 'resourceLevel', 'primaryMotivation', 'confidence', 'createdByRef'] as const;
    for (const field of strFields) {
        if (!mergedActor[field]) {
            const match = allMatchingActors.find(a => a[field]);
            if (match) mergedActor[field] = match[field] as any;
        }
    }

    // Merge description if current is missing or very short
    if (!mergedActor.description || mergedActor.description.length < 20) {
        const bestDescActor = allMatchingActors
            .filter(a => a.description && a.description.length >= 20)
            .sort((a, b) => (b.description?.length || 0) - (a.description?.length || 0))[0];
        if (bestDescActor) {
            mergedActor.description = bestDescActor.description;
        }
    }

    // Merge distinct array fields
    const arrayFields = ['aliases', 'goals', 'labels'] as const;
    for (const field of arrayFields) {
        const combined = new Set(mergedActor[field] as string[]);
        for (const a of allMatchingActors) {
            for (const item of (a[field] as string[] || [])) {
                combined.add(item);
            }
        }
        mergedActor[field] = Array.from(combined);
    }

    // Merge external references safely
    const combinedRefs = new Map<string, any>();
    for (const a of [mergedActor, ...allMatchingActors]) {
        for (const ref of (a.externalReferences as any[] || [])) {
            const key = ref.url || ref.source_name;
            if (key && !combinedRefs.has(key)) {
                combinedRefs.set(key, ref);
            }
        }
    }
    mergedActor.externalReferences = Array.from(combinedRefs.values());

    // Resolve STIX identity UUIDs to human-readable source names
    const STIX_SOURCES: Record<string, string> = {
        'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5': 'The MITRE Corporation',
        'identity--bae15c91-ed56-4965-a26e-4d3fd1e2e0e5': 'Proofpoint',
        'identity--b6d13e0a-7c22-4012-8de6-6a29f75e3975': 'Mandiant (Google)',
        'identity--4d8cd09a-2f04-48f0-88e6-6dbb37e6dca0': 'Microsoft Threat Intelligence',
        'identity--5dcf0a7a-875b-470b-a51b-52c6a4e5cf1f': 'Trend Micro',
    };
    const createdByRef = mergedActor.createdByRef || '';
    const sourceName = STIX_SOURCES[createdByRef] || createdByRef || null;

    // Map PostgreSQL fields to frontend-expected field names
    const mappedData = {
        id: mergedActor.id, // Retain original ID
        stixId: mergedActor.stixId,
        name: mergedActor.name,
        aliases: mergedActor.aliases || [],
        description: mergedActor.description || '',
        sophistication: mergedActor.sophistication,
        resourceLevel: mergedActor.resourceLevel,
        primaryMotivation: mergedActor.primaryMotivation,
        goals: mergedActor.goals || [],
        labels: mergedActor.labels || [],
        confidence: mergedActor.confidence,
        createdByRef: createdByRef,
        sourceName: sourceName,
        externalReferences: mergedActor.externalReferences || [],
        createdAt: mergedActor.createdAt,
        updatedAt: mergedActor.updatedAt,
    };

    return c.json({ success: true, data: mappedData });
});

// ============================================================================
// Threat Actors — Cursor Pagination (PostgreSQL direct)
// ============================================================================

router.get('/threats/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    let whereClause = '';
    if (cursor) {
        const op = direction === 'next' ? '<' : '>';
        whereClause = `WHERE (updated_at, id::text) ${op} ('${escSql(cursor.timestamp)}', '${escSql(cursor.id)}')`;
    }

    const orderDir = direction === 'next' ? 'DESC' : 'ASC';

    const result = await rawQuery(
        `SELECT * FROM threat_actors ${whereClause}
         ORDER BY updated_at ${orderDir} NULLS LAST, id ${orderDir}
         LIMIT ${limit + 1}`
    );

    const rows = result.rows || [];
    if (direction === 'prev') rows.reverse();

    const response = buildCursorResponse(rows, limit, (row: Record<string, unknown>) => ({
        timestamp: String(row.updated_at || row.created_at || ''),
        id: String(row.id || ''),
    }));

    return c.json({ success: true, ...response });
});

// ============================================================================
// Indicators
// ============================================================================

router.get('/indicators', async (c) => {
    const { page, pageSize } = PaginationSchema.parse(c.req.query());

    const items = await db.select()
        .from(indicators)
        .orderBy(desc(indicators.updatedAt))
        .limit(pageSize)
        .offset((page - 1) * pageSize);

    const [{ total }] = await db.select({ total: count() }).from(indicators);

    return c.json({
        success: true,
        data: {
            items,
            pagination: paginate(page, pageSize, total),
        },
    });
});

// ============================================================================
// Indicators — Cursor Pagination (PostgreSQL direct)
// ============================================================================

router.get('/indicators/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    let whereClause = '';
    if (cursor) {
        const op = direction === 'next' ? '<' : '>';
        whereClause = `WHERE (updated_at, id::text) ${op} ('${escSql(cursor.timestamp)}', '${escSql(cursor.id)}')`;
    }

    const orderDir = direction === 'next' ? 'DESC' : 'ASC';

    const result = await rawQuery(
        `SELECT * FROM indicators ${whereClause}
         ORDER BY updated_at ${orderDir} NULLS LAST, id ${orderDir}
         LIMIT ${limit + 1}`
    );

    const rows = result.rows || [];
    if (direction === 'prev') rows.reverse();

    const response = buildCursorResponse(rows, limit, (row: Record<string, unknown>) => ({
        timestamp: String(row.updated_at || row.created_at || ''),
        id: String(row.id || ''),
    }));

    return c.json({ success: true, ...response });
});

// ============================================================================
// Threat Actor CRUD (Phase AG — TheHive inspired)
// ============================================================================

import { requireAuth, requireRole } from '../../middleware/auth';
import { CreateThreatActorSchema, UpdateThreatActorSchema } from '../../lib/schemas';

/** POST /v1/threats/actors — Create a new threat actor */
router.post('/threats/actors', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = CreateThreatActorSchema.parse(await c.req.json().catch(() => ({})));

    const [created] = await db.insert(threatActors).values({
        name: body.name,
        stixId: `threat-actor--${crypto.randomUUID()}`,
        description: body.description,
        aliases: body.aliases,
        sophistication: body.sophistication || null,
        resourceLevel: body.resourceLevel || null,
        primaryMotivation: body.primaryMotivation || null,
        labels: body.tags,
    }).returning();

    return c.json({ success: true, data: created }, 201);
});

/** PUT /v1/threats/actors/:id — Update threat actor */
router.put('/threats/actors/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = UpdateThreatActorSchema.parse(await c.req.json().catch(() => ({})));

    const set: Record<string, unknown> = { updatedAt: new Date() };
    if (body.name) set.name = body.name;
    if (body.description) set.description = body.description;
    if (body.aliases) set.aliases = body.aliases;
    if (body.sophistication) set.sophistication = body.sophistication;
    if (body.resourceLevel) set.resourceLevel = body.resourceLevel;
    if (body.primaryMotivation) set.primaryMotivation = body.primaryMotivation;
    if (body.tags) set.labels = body.tags;

    const [updated] = await db.update(threatActors)
        .set(set)
        .where(eq(threatActors.id, id))
        .returning();

    if (!updated) throw new NotFoundError('Threat actor', id);
    return c.json({ success: true, data: updated });
});

/** DELETE /v1/threats/actors/:id — Delete threat actor */
router.delete('/threats/actors/:id', requireAuth, requireRole('admin'), async (c) => {
    const { id } = c.req.param();

    const [deleted] = await db.delete(threatActors)
        .where(eq(threatActors.id, id))
        .returning({ id: threatActors.id });

    if (!deleted) throw new NotFoundError('Threat actor', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// ============================================================================
// Actor Enrichment (LLM-driven — fills null/empty STIX fields from description)
// ============================================================================

import { enrichActor } from '../../services/actorEnrichment';

/** POST /v1/threats/:id/enrich — enrich a single actor; admin/analyst only */
router.post('/threats/:id/enrich', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    const whereClause = isUUID ? eq(threatActors.id, id) : eq(threatActors.name, decodeURIComponent(id));

    const [actor] = await db.select().from(threatActors).where(whereClause).limit(1);
    if (!actor) throw new NotFoundError('Threat actor', id);

    // Historical rows may have scalars in jsonb array columns — coerce.
    const safeArr = (v: unknown): string[] =>
        Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

    const enrichment = await enrichActor({
        id: actor.id,
        name: actor.name,
        description: actor.description,
        aliases: safeArr(actor.aliases),
        sophistication: actor.sophistication,
        resourceLevel: actor.resourceLevel,
        primaryMotivation: actor.primaryMotivation,
        goals: safeArr(actor.goals),
        labels: safeArr(actor.labels),
        confidence: actor.confidence as string | null,
    });

    const filledKeys = Object.keys(enrichment);
    if (filledKeys.length === 0) {
        return c.json({ success: true, data: { id: actor.id, filled: [], message: 'No new fields could be inferred' } });
    }

    const [updated] = await db.update(threatActors)
        .set({ ...enrichment, updatedAt: new Date() })
        .where(eq(threatActors.id, actor.id))
        .returning();

    return c.json({
        success: true,
        data: {
            id: actor.id,
            filled: filledKeys,
            actor: updated,
        },
    });
});

/**
 * POST /v1/threats/enrich/bulk — enrich up to N actors that have at least
 * one null field. Returns counts; admin only. Heavy operation — rate-limited
 * by Gemini's free-tier ~150 RPM in practice.
 */
router.post('/threats/enrich/bulk', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json<{ limit?: number }>().catch(() => ({} as { limit?: number }));
    const limit = Math.min(Math.max(body.limit ?? 50, 1), 500);

    // Pick actors with at least one null field AND a meaningful description.
    // Note: older rows may store a scalar in `aliases`/`labels` instead of an
    // array — `jsonb_array_length` throws 22023 on those, so we guard with
    // `jsonb_typeof(...) = 'array'` before calling length.
    const candidates = await db.execute(sql.raw(`
        SELECT id, name, description, aliases, sophistication, resource_level,
               primary_motivation, goals, labels, confidence
        FROM threat_actors
        WHERE LENGTH(COALESCE(description, '')) >= 40
          AND (
              sophistication IS NULL OR
              resource_level IS NULL OR
              primary_motivation IS NULL OR
              aliases IS NULL OR jsonb_typeof(aliases) <> 'array' OR jsonb_array_length(aliases) = 0 OR
              labels  IS NULL OR jsonb_typeof(labels)  <> 'array' OR jsonb_array_length(labels)  = 0
          )
        ORDER BY updated_at DESC
        LIMIT ${limit}
    `)) as unknown as Array<{
        id: string; name: string; description: string | null;
        aliases: string[] | null; sophistication: string | null;
        resource_level: string | null; primary_motivation: string | null;
        goals: string[] | null; labels: string[] | null; confidence: string | null;
    }>;

    let enrichedCount = 0;
    let skippedCount = 0;
    const errors: Array<{ id: string; name: string; error: string }> = [];

    /** Coerce jsonb scalars/null back to an array — historical rows may
     *  have a string in aliases/labels/goals due to upstream ingestion bugs. */
    const arr = (v: unknown): string[] => Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

    for (const row of candidates) {
        try {
            const enrichment = await enrichActor({
                id: row.id,
                name: row.name,
                description: row.description,
                aliases: arr(row.aliases),
                sophistication: row.sophistication,
                resourceLevel: row.resource_level,
                primaryMotivation: row.primary_motivation,
                goals: arr(row.goals),
                labels: arr(row.labels),
                confidence: row.confidence as string | null,
            });

            if (Object.keys(enrichment).length === 0) {
                skippedCount++;
                continue;
            }

            await db.update(threatActors)
                .set({ ...enrichment, updatedAt: new Date() })
                .where(eq(threatActors.id, row.id));
            enrichedCount++;
        } catch (err) {
            errors.push({ id: row.id, name: row.name, error: (err as Error).message });
        }
    }

    return c.json({
        success: true,
        data: {
            considered: candidates.length,
            enriched: enrichedCount,
            skipped: skippedCount,
            errors,
        },
    });
});

export default router;
