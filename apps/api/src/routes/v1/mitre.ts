/**
 * MITRE ATT&CK Routes (Techniques, Threat Actors, Malware, Tools)
 *
 * Extracted from v1.ts — MITRE framework data endpoints.
 */

import { Hono } from 'hono';
import { db, sql, rawQuery } from '@rinjani/db';
import * as opensearch from '../../services/opensearch';
import { NotFoundError } from '../../lib/errors';
import {
    PaginationSchema, SearchQuerySchema, TechniqueFilterSchema,
} from '../../lib/schemas';
import { paginate } from './helpers';

const router = new Hono();

// ============================================================================
// MITRE ATT&CK - Techniques
// ============================================================================

router.get('/techniques', async (c) => {
    const { page, pageSize, q: search, platform, tactic: tacticId } = TechniqueFilterSchema.parse(c.req.query());

    // Build parameterized conditions to prevent SQL injection
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    if (search) {
        params.push(`%${search}%`);
        conditions.push(`(name ILIKE $${params.length} OR mitre_id ILIKE $${params.length})`);
    }
    if (platform) {
        params.push(`%${platform}%`);
        conditions.push(`platforms::text ILIKE $${params.length}`);
    }
    if (tacticId) {
        params.push(`%${tacticId}%`);
        conditions.push(`tactic_ids::text ILIKE $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Parameterize LIMIT and OFFSET to prevent injection
    params.push(pageSize);
    const limitParam = params.length;
    params.push((page - 1) * pageSize);
    const offsetParam = params.length;

    const dataQuery = `SELECT * FROM techniques ${whereClause} ORDER BY mitre_id LIMIT $${limitParam} OFFSET $${offsetParam}`;
    const countQuery = `SELECT COUNT(*) FROM techniques ${whereClause}`;

    // Batch data + count queries in parallel
    const [items, countResult] = await Promise.all([
        rawQuery(dataQuery),
        rawQuery<{ count: string }>(countQuery),
    ]);
    const total = Number(countResult.rows[0]?.count ?? 0);

    return c.json({
        success: true,
        data: {
            items,
            pagination: paginate(page, pageSize, total),
        },
    });
});

router.get('/techniques/:mitreId', async (c) => {
    const { mitreId } = c.req.param();
    const items = await db.execute(sql`SELECT * FROM techniques WHERE mitre_id = ${mitreId}`) as unknown as Record<string, unknown>[];
    if (!items[0]) throw new NotFoundError('Technique', mitreId);
    return c.json({ success: true, data: items[0] });
});

// ============================================================================
// MITRE ATT&CK - Threat Actors
// ============================================================================

router.get('/threat-actors', async (c) => {
    const { page, pageSize, q } = SearchQuerySchema.parse(c.req.query());

    // Use OpenSearch for fast search with facets
    const result = await opensearch.unifiedSearch({
        query: q || '',
        filters: {
            entityType: ['threat-actor'],
        },
        sort: { field: 'updatedAt', order: 'desc' },
        pagination: { page, limit: pageSize },
        aggregations: true,
    });

    // Map OpenSearch fields to frontend-expected names for actors
    const mappedItems = result.items.map((item: Record<string, unknown>) => ({
        ...item,
        name: item.title || item.value,
        aliases: item.tags || [],
        sophistication: item.sophistication || null,
        resourceLevel: item.resourceLevel || null,
        primaryMotivation: item.primaryMotivation || null,
        firstSeen: item.createdAt,
    }));

    return c.json({
        success: true,
        data: {
            items: mappedItems,
            pagination: paginate(page, pageSize, result.total),
            facets: result.facets,
            took: result.took,
        },
    });
});

// ============================================================================
// MITRE ATT&CK - Threat Actor Detail
// ============================================================================

router.get('/threat-actors/:id', async (c) => {
    const { id } = c.req.param();

    // Use OpenSearch getById for lookup by UUID or STIX ID
    const result = await opensearch.getById(id, 'actor');

    if (!result.item) {
        throw new NotFoundError('Threat Actor', id);
    }

    const item = result.item;
    const mappedData = {
        ...item,
        name: item.title || item.value,
        aliases: item.tags || [],
        sophistication: item.sophistication || null,
        resourceLevel: item.resourceLevel || null,
        primaryMotivation: item.primaryMotivation || null,
        firstSeen: item.createdAt,
        lastSeen: item.updatedAt,
    };

    return c.json({ success: true, data: mappedData, took: result.took });
});
// ============================================================================
// MITRE ATT&CK - Malware
// ============================================================================

router.get('/malware', async (c) => {
    const { page, pageSize } = PaginationSchema.parse(c.req.query());

    const items = await db.execute(sql`
        SELECT * FROM malware 
        ORDER BY name 
        LIMIT ${pageSize} OFFSET ${(page - 1) * pageSize}
    `) as unknown as Record<string, unknown>[];

    const countResult = await db.execute(sql`SELECT COUNT(*) FROM malware`) as unknown as { count: number }[];
    const total = Number(countResult[0]?.count ?? 0);

    return c.json({
        success: true,
        data: {
            items,
            pagination: paginate(page, pageSize, total),
        },
    });
});

// ============================================================================
// MITRE ATT&CK - Tools
// ============================================================================

router.get('/tools', async (c) => {
    const { page, pageSize } = PaginationSchema.parse(c.req.query());

    const items = await db.execute(sql`
        SELECT * FROM tools 
        ORDER BY name 
        LIMIT ${pageSize} OFFSET ${(page - 1) * pageSize}
    `) as unknown as Record<string, unknown>[];

    const countResult = await db.execute(sql`SELECT COUNT(*) FROM tools`) as unknown as { count: number }[];
    const total = Number(countResult[0]?.count ?? 0);

    return c.json({
        success: true,
        data: {
            items,
            pagination: paginate(page, pageSize, total),
        },
    });
});

// ============================================================================
// MITRE ATT&CK - Matrix (Navigator Heatmap Data)
// ============================================================================

/**
 * GET /mitre/matrix
 *
 * Returns a pre-computed ATT&CK matrix structure suitable for rendering
 * a Navigator-style heatmap. Single-call endpoint to avoid N+1 from frontend.
 *
 * Response shape:
 * {
 *   tactics: [{ id, mitreId, name, shortName }],
 *   techniques: [{ id, mitreId, name, tacticIds, actorCount, usageCount }],
 *   actors: [{ id, name, stixId, techniqueMitreIds }]
 * }
 */
router.get('/mitre/matrix', async (c) => {
    // Try Redis cache first (5-minute TTL)
    let cached: string | null = null;
    try {
        const { cacheConnection } = await import('../../services/redis');
        cached = await cacheConnection.get('rjn:mitre:matrix:cache');
        if (cached) {
            c.header('X-Cache', 'HIT');
            return c.json({ success: true, data: JSON.parse(cached) });
        }
    } catch {
        // Redis unavailable — proceed without cache
    }

    // 1. Fetch all tactics
    const tacticsRaw = await db.execute(
        sql`SELECT id, mitre_id, name, short_name FROM tactics ORDER BY mitre_id`
    ) as unknown as Array<{ id: string; mitre_id: string; name: string; short_name: string }>;

    const tactics = tacticsRaw.map((t) => ({
        id: t.id,
        mitreId: t.mitre_id,
        name: t.name,
        shortName: t.short_name || t.name,
    }));

    // 2. Fetch all techniques with their tactic mappings
    const techniquesRaw = await db.execute(
        sql`SELECT id, mitre_id, name, tactic_ids, platforms, description FROM techniques ORDER BY mitre_id`
    ) as unknown as Array<{
        id: string;
        mitre_id: string;
        name: string;
        tactic_ids: string[] | string | null;
        platforms: string[] | string | null;
        description: string | null;
    }>;

    // 3. Fetch STIX relationships with descriptions for MITRE ID resolution
    //    The `relationships` table stores STIX IDs (intrusion-set--xxx, attack-pattern--xxx)
    //    but entity tables use MITRE IDs (G0094, T1059). The description field contains
    //    markdown links like [Name](https://attack.mitre.org/techniques/T1059) that we
    //    parse with regex to resolve the mapping (same approach as syncRelationships.ts).
    let usesRelationships: Array<{
        source_id: string;
        target_id: string;
        description: string | null;
    }> = [];
    try {
        usesRelationships = await db.execute(
            sql`SELECT source_id, target_id, description
                FROM relationships
                WHERE relationship_type = 'uses'
                  AND source_type = 'intrusion-set'
                  AND target_type = 'attack-pattern'`
        ) as unknown as typeof usesRelationships;
    } catch {
        // Table unavailable — continue with empty relationships
    }

    // 4. Fetch threat actors for mapping
    const actorsRaw = await db.execute(
        sql`SELECT id, name, stix_id FROM threat_actors ORDER BY name`
    ) as unknown as Array<{ id: string; name: string; stix_id: string | null }>;

    // 5. Build STIX ID → MITRE ID lookup from the MITRE ATT&CK STIX bundle
    //    (Same approach as syncRelationships.ts — cached in Redis for 24h)
    const STIX_CACHE_KEY = 'rjn:stix:lookup';
    let stixLookup: Record<string, string> = {};

    try {
        const { cacheConnection } = await import('../../services/redis');
        const cached = await cacheConnection.get(STIX_CACHE_KEY);
        if (cached) {
            stixLookup = JSON.parse(cached);
        } else {
            // Fetch STIX bundle and build lookup
            const ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
            const resp = await fetch(ATTACK_URL);
            if (resp.ok) {
                const bundle = await resp.json() as {
                    objects: Array<{
                        type: string;
                        id: string;
                        external_references?: Array<{ source_name: string; external_id?: string }>;
                    }>;
                };
                for (const obj of bundle.objects) {
                    const ref = obj.external_references?.find(
                        (r: { source_name: string }) => r.source_name === 'mitre-attack'
                    );
                    if (ref?.external_id) {
                        stixLookup[obj.id] = ref.external_id;
                    }
                }
                // Cache for 24 hours
                await cacheConnection.setex(STIX_CACHE_KEY, 86400, JSON.stringify(stixLookup));
            }
        }
    } catch {
        // STIX lookup unavailable — continue with empty mappings
    }

    // Per-technique MITRE ID → Set of actor STIX IDs
    const techniqueActors = new Map<string, Set<string>>();
    // Per-actor STIX source_id → Set of technique MITRE IDs
    const actorTechMap = new Map<string, Set<string>>();
    // Actor STIX source_id → display name (from description markdown)
    const actorNamesFromDesc = new Map<string, string>();

    for (const rel of usesRelationships) {
        // Resolve attack-pattern STIX ID → technique MITRE ID via lookup
        const techMitreId = stixLookup[rel.target_id];
        if (!techMitreId) continue;

        // Track technique → actor mapping
        if (!techniqueActors.has(techMitreId)) {
            techniqueActors.set(techMitreId, new Set());
        }
        techniqueActors.get(techMitreId)!.add(rel.source_id);

        // Track actor → technique mapping
        if (!actorTechMap.has(rel.source_id)) {
            actorTechMap.set(rel.source_id, new Set());
        }
        actorTechMap.get(rel.source_id)!.add(techMitreId);

        // Extract actor name from first markdown link in description
        if (!actorNamesFromDesc.has(rel.source_id)) {
            const desc = rel.description || '';
            const nameMatch = desc.match(/^\[([^\]]+)\]/);
            if (nameMatch) {
                actorNamesFromDesc.set(rel.source_id, nameMatch[1]);
            }
        }
    }

    // Parse tactic_ids from techniques (may be JSON array or comma-separated)
    const parseTacticIds = (raw: string[] | string | null): string[] => {
        if (!raw) return [];
        if (Array.isArray(raw)) return raw;
        try { return JSON.parse(raw); } catch { /* ignore */ }
        return raw.split(',').map((s: string) => s.trim()).filter(Boolean);
    };

    // Build technique objects with actor counts
    const techniques = techniquesRaw.map((t) => ({
        id: t.id,
        mitreId: t.mitre_id,
        name: t.name,
        tacticIds: parseTacticIds(t.tactic_ids),
        platforms: parseTacticIds(t.platforms),
        description: t.description?.substring(0, 200) || null,
        actorCount: techniqueActors.get(t.mitre_id)?.size || 0,
        usageCount: techniqueActors.get(t.mitre_id)?.size || 0,
    }));

    // Build actor objects — match intrusion-set source IDs to threat_actors by name
    const actorByNameLower = new Map<string, { id: string; name: string; stixId: string | null }>();
    for (const a of actorsRaw) {
        actorByNameLower.set(a.name.toLowerCase(), { id: a.id, name: a.name, stixId: a.stix_id });
    }

    const actors: Array<{
        id: string;
        name: string;
        stixId: string | null;
        techniqueMitreIds: string[];
    }> = [];

    for (const [sourceId, techIds] of actorTechMap.entries()) {
        // Use STIX lookup to get group ID, then use description for display name
        const descName = actorNamesFromDesc.get(sourceId);
        const matched = descName ? actorByNameLower.get(descName.toLowerCase()) : undefined;

        actors.push({
            id: matched?.id || sourceId,
            name: matched?.name || descName || stixLookup[sourceId] || sourceId.replace('intrusion-set--', 'IS-'),
            stixId: matched?.stixId || sourceId,
            techniqueMitreIds: Array.from(techIds),
        });
    }

    // Sort actors by name
    actors.sort((a, b) => a.name.localeCompare(b.name));

    const result = { tactics, techniques, actors };

    // Cache in Redis for 5 minutes
    try {
        const { cacheConnection } = await import('../../services/redis');
        await cacheConnection.setex('rjn:mitre:matrix:cache', 300, JSON.stringify(result));
    } catch {
        // Caching failed silently
    }

    c.header('X-Cache', 'MISS');
    return c.json({
        success: true,
        data: result,
        meta: {
            tacticsCount: tactics.length,
            techniquesCount: techniques.length,
            actorsWithCoverage: actors.length,
        },
    });
});

// ============================================================================
// CTI home — lightweight aggregates
// ============================================================================

/**
 * GET /v1/mitre/coverage
 *
 * Per-tactic technique count, suitable for an ATT&CK coverage strip on the
 * home page. Cheaper than /mitre/matrix (no relationships, no actor join).
 * Note: `techniques.tactic_ids` is stored as a JSONB string containing a
 * JSON array (double-encoded) so we parse it via `#>> '{}'` then re-cast.
 */
router.get('/mitre/coverage', async (c) => {
    const rows = await db.execute(sql`
        SELECT
          t.mitre_id  AS mitre_id,
          t.name      AS name,
          t.short_name AS short_name,
          COUNT(DISTINCT tech.id) AS technique_count
        FROM tactics t
        LEFT JOIN techniques tech
          ON (tech.tactic_ids #>> '{}')::jsonb @> to_jsonb(t.mitre_id::text)
        GROUP BY t.mitre_id, t.name, t.short_name
        ORDER BY t.mitre_id
    `) as unknown as Array<{
        mitre_id: string;
        name: string;
        short_name: string | null;
        technique_count: string | number;
    }>;

    const tactics = rows.map(r => ({
        mitreId: r.mitre_id,
        name: r.name,
        shortName: r.short_name ?? r.name,
        techniqueCount: Number(r.technique_count) || 0,
    }));

    const totalTechniques = tactics.reduce((sum, t) => sum + t.techniqueCount, 0);

    return c.json({
        success: true,
        data: { tactics, totalTechniques },
    });
});

/**
 * GET /v1/actors/active?limit=10
 *
 * Most-recently-active threat actors, ordered by COALESCE(last_seen,
 * updated_at) DESC. Returns enough surface to render a watchlist row:
 * name, aliases, country, sophistication, last-seen, primary motivation.
 *
 * No expensive joins — the home page block calls this once for an
 * overview; deeper drill-down lives on the actor detail page.
 */
router.get('/actors/active', async (c) => {
    const limitRaw = Number(c.req.query('limit') ?? 10);
    const limit = Math.min(Math.max(Math.floor(limitRaw) || 10, 1), 50);

    // Prefer actors with curated activity (`last_seen IS NOT NULL`). They have
    // real attribution dates; the rest are bulk-synced metadata records.
    // `aliases` is stored as a JSONB *string* containing JSON (double-encoded),
    // so it's parsed via `#>> '{}'` then re-cast in the mapper below.
    const rows = await db.execute(sql`
        SELECT
          id,
          stix_id,
          name,
          (aliases #>> '{}')::jsonb AS aliases_array,
          country,
          sophistication,
          primary_motivation,
          first_seen,
          last_seen,
          updated_at
        FROM threat_actors
        WHERE last_seen IS NOT NULL
        ORDER BY last_seen DESC
        LIMIT ${limit}
    `) as unknown as Array<{
        id: string;
        stix_id: string | null;
        name: string;
        aliases_array: unknown;
        country: string | null;
        sophistication: string | null;
        primary_motivation: string | null;
        first_seen: Date | string | null;
        last_seen: Date | string | null;
        updated_at: Date | string | null;
    }>;

    const actors = rows.map(r => ({
        id: r.id,
        stixId: r.stix_id,
        name: r.name,
        aliases: Array.isArray(r.aliases_array) ? (r.aliases_array as string[]) : [],
        country: r.country,
        sophistication: r.sophistication,
        primaryMotivation: r.primary_motivation,
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
        updatedAt: r.updated_at,
    }));

    return c.json({
        success: true,
        data: { actors },
    });
});

export default router;
