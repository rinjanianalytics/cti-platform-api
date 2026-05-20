/**
 * GraphQL Resolvers
 *
 * Query resolvers for threat intelligence data.
 * Includes relationship resolvers for cross-entity linking and
 * Neo4j-backed graph exploration queries.
 */

import { and, count, db, desc, eq, sql, ilike, inArray } from '@rinjani/db';
import { threatActors, iocs, vulnerabilities, mitreRelationships, sightings } from '@rinjani/db/schema';
import { builder, SearchResultType } from './schema';

// Neo4j graph services
import {
    graphSearch,
    neighborhoodExpand,
    findShortestPath,
    getAttackTree,
    iocPivot,
} from '../services/neo4jGraph';
import {
    findRelatedActors,
    actorAttribution,
} from '../services/neo4jGraph';

// Sighting service
import {
    addSighting as addSightingSvc,
    getRecentSightings,
    getSightingStats as getSightingStatsSvc,
} from '../services/sightings';

// ============================================================================
// Helpers
// ============================================================================

/**
 * Safely extract rows from db.execute() results.
 * Drizzle's execute() may return { rows: [...] } or the array directly
 * depending on the driver version.
 */
function extractRows(result: unknown): Record<string, unknown>[] {
    if (Array.isArray(result)) return result as Record<string, unknown>[];
    if (result && typeof result === 'object' && 'rows' in result) {
        return (result as { rows: Record<string, unknown>[] }).rows ?? [];
    }
    return [];
}

// ============================================================================
// Relationship Resolvers — extend existing types with cross-entity fields
// ============================================================================

// ── ThreatActor → IOCs (via mitreRelationships table) ──
builder.objectField('ThreatActor', 'iocs', (t) =>
    t.field({
        type: ['IOC'],
        args: {
            limit: t.arg.int({ defaultValue: 10 }),
        },
        resolve: async (actor, args) => {
            const rels = await db.select()
                .from(mitreRelationships)
                .where(
                    sql`${mitreRelationships.sourceType} = 'threat_actor'
                        AND ${mitreRelationships.sourceId} = ${actor.stixId}
                        AND ${mitreRelationships.targetType} = 'indicator'`
                )
                .limit(args.limit ?? 10);

            const targetIds = rels.map(r => r.targetId);
            if (targetIds.length === 0) return [];

            const results = await db.select()
                .from(iocs)
                .where(sql`${iocs.id}::text = ANY(${targetIds}) OR ${iocs.value} = ANY(${targetIds})`)
                .limit(args.limit ?? 10);

            return results.map(r => ({
                id: r.id,
                type: r.type,
                value: r.value,
                source: r.source,
                threatType: r.threatType,
                severity: r.severity ?? null,
                confidence: r.confidence ?? null,
                tags: r.tags ?? null,
                isMalicious: false,
                firstSeen: r.firstSeen,
                lastSeen: r.lastSeen,
            }));
        },
    }),
);

// ── ThreatActor → Techniques (via relationships table + stix_id bridge) ──
builder.objectField('ThreatActor', 'techniques', (t) =>
    t.field({
        type: ['Technique'],
        args: {
            limit: t.arg.int({ defaultValue: 20 }),
        },
        resolve: async (actor, args) => {
            const limit = args.limit ?? 20;
            const actorName = actor.name;
            const namePattern = `%[${actorName}]%`;

            // Single query: find source_id by actor name in relationship descriptions,
            // then join to techniques via stix_id bridge
            const result = await db.execute(
                sql`SELECT DISTINCT t.id, t.mitre_id, t.name, t.description, t.platforms,
                           t.tactic_ids, t.detection, t.url
                    FROM relationships r
                    JOIN techniques t ON t.stix_id = r.target_id
                    WHERE r.source_id IN (
                        SELECT DISTINCT source_id FROM relationships
                        WHERE source_type = 'intrusion-set'
                          AND description ILIKE ${namePattern}
                    )
                      AND r.target_type = 'attack-pattern'
                      AND r.relationship_type = 'uses'
                    ORDER BY t.mitre_id
                    LIMIT ${limit}`
            );
            const rows = extractRows(result);
            return rows.map(row => {
                // Parse JSONB columns that come as strings from raw SQL
                let platforms: string[] = [];
                let tacticIds: string[] = [];
                try { platforms = typeof row.platforms === 'string' ? JSON.parse(row.platforms) : (row.platforms as string[]) ?? []; } catch { /* ignore */ }
                try { tacticIds = typeof row.tactic_ids === 'string' ? JSON.parse(row.tactic_ids) : (row.tactic_ids as string[]) ?? []; } catch { /* ignore */ }

                return {
                    id: String(row.id),
                    mitreId: String(row.mitre_id),
                    name: String(row.name),
                    description: row.description as string | null,
                    platforms,
                    tacticIds,
                    detection: row.detection as string | null,
                    url: row.url as string | null,
                };
            });
        },
    }),
);

// ── ThreatActor → Related Actors (via Neo4j shared techniques) ──
builder.objectField('ThreatActor', 'relatedActors', (t) =>
    t.field({
        type: ['GraphNodeGQL'],
        nullable: true,
        resolve: async (actor) => {
            try {
                const result = await findRelatedActors(actor.name, 1);
                return result.nodes;
            } catch {
                return null; // Neo4j may not be available
            }
        },
    }),
);

// ── IOC → Attribution chain (via Neo4j) ──
builder.objectField('IOC', 'relatedActors', (t) =>
    t.field({
        type: 'GraphResultGQL',
        nullable: true,
        resolve: async (ioc) => {
            try {
                const result = await actorAttribution(ioc.value, 10);
                return { nodes: result.nodes, edges: result.edges };
            } catch {
                return null;
            }
        },
    }),
);

// ── Vulnerability → IOCs (via mitreRelationships table) ──
builder.objectField('Vulnerability', 'relatedIocs', (t) =>
    t.field({
        type: ['IOC'],
        args: {
            limit: t.arg.int({ defaultValue: 10 }),
        },
        resolve: async (vuln, args) => {
            const rels = await db.select()
                .from(mitreRelationships)
                .where(
                    sql`${mitreRelationships.sourceType} = 'vulnerability'
                        AND ${mitreRelationships.sourceId} = ${vuln.cveId}
                        AND ${mitreRelationships.targetType} = 'indicator'`
                )
                .limit(args.limit ?? 10);

            const targetIds = rels.map(r => r.targetId);
            if (targetIds.length === 0) return [];

            const results = await db.select()
                .from(iocs)
                .where(sql`${iocs.id}::text = ANY(${targetIds}) OR ${iocs.value} = ANY(${targetIds})`)
                .limit(args.limit ?? 10);

            return results.map(r => ({
                id: r.id,
                type: r.type,
                value: r.value,
                source: r.source,
                threatType: r.threatType,
                severity: r.severity ?? null,
                confidence: r.confidence ?? null,
                tags: r.tags ?? null,
                isMalicious: false,
                firstSeen: r.firstSeen,
                lastSeen: r.lastSeen,
            }));
        },
    }),
);

// ============================================================================
// Queries
// ============================================================================

builder.queryType({
    fields: (t) => ({
        // ── Existing: Threat Actors ──
        threatActors: t.field({
            type: ['ThreatActor'],
            args: {
                limit: t.arg.int({ defaultValue: 25 }),
                offset: t.arg.int({ defaultValue: 0 }),
                since: t.arg.string(),
            },
            resolve: async (_root, args) => {
                let query = db.select()
                    .from(threatActors);

                if (args.since) {
                    query = query.where(
                        sql`${threatActors.lastSeen} >= ${args.since}` as unknown as ReturnType<typeof eq>
                    ) as typeof query;
                }

                const items = await query
                    .limit(args.limit ?? 25)
                    .offset(args.offset ?? 0)
                    .orderBy(desc(threatActors.lastSeen));

                return items.map(item => ({
                    id: item.id,
                    stixId: item.stixId,
                    name: item.name,
                    aliases: item.aliases ?? [],
                    description: item.description,
                    primaryMotivation: item.primaryMotivation,
                    sophistication: item.sophistication,
                    country: item.country ?? null,
                    firstSeen: item.firstSeen ?? null,
                    lastSeen: item.lastSeen ?? null,
                }));
            },
        }),

        threatActor: t.field({
            type: 'ThreatActor',
            nullable: true,
            args: {
                id: t.arg.string({ required: true }),
            },
            resolve: async (_root, args) => {
                const [item] = await db.select()
                    .from(threatActors)
                    .where(eq(threatActors.id, args.id))
                    .limit(1);

                if (!item) return null;

                return {
                    id: item.id,
                    stixId: item.stixId,
                    name: item.name,
                    aliases: item.aliases ?? [],
                    description: item.description,
                    primaryMotivation: item.primaryMotivation,
                    sophistication: item.sophistication,
                    country: item.country ?? null,
                    firstSeen: item.firstSeen ?? null,
                    lastSeen: item.lastSeen ?? null,
                };
            },
        }),

        // ── Existing: Techniques ──
        techniques: t.field({
            type: ['Technique'],
            args: {
                limit: t.arg.int({ defaultValue: 50 }),
                platform: t.arg.string(),
                tactic: t.arg.string(),
            },
            resolve: async (_root, args) => {
                const limit = args.limit ?? 50;
                const platformPattern = args.platform ? `%${args.platform}%` : null;
                const tacticPattern = args.tactic ? `%${args.tactic}%` : null;

                // Parameter-bound filters: NULL pattern disables the predicate.
                const result = await db.execute(
                    sql`SELECT * FROM techniques
                        WHERE (${platformPattern}::text IS NULL OR platforms::text ILIKE ${platformPattern})
                          AND (${tacticPattern}::text IS NULL OR tactic_ids::text ILIKE ${tacticPattern})
                        ORDER BY mitre_id
                        LIMIT ${limit}`
                );
                const rows = extractRows(result);

                return rows.map((row) => ({
                    id: String(row.id),
                    mitreId: String(row.mitre_id),
                    name: String(row.name),
                    description: row.description as string | null,
                    platforms: (row.platforms as string[]) ?? [],
                    tacticIds: (row.tactic_ids as string[]) ?? [],
                    detection: row.detection as string | null,
                    url: row.url as string | null,
                }));
            },
        }),

        // ── Existing: Tactics ──
        tactics: t.field({
            type: ['Tactic'],
            resolve: async () => {
                const result = await db.execute(sql`SELECT * FROM tactics ORDER BY mitre_id`);
                const rows = extractRows(result);

                return rows.map((row) => ({
                    id: String(row.id),
                    mitreId: String(row.mitre_id),
                    name: String(row.name),
                    description: row.description as string | null,
                    shortName: row.short_name as string | null,
                }));
            },
        }),

        // ── Existing: IOCs ──
        iocs: t.field({
            type: 'IOCConnection',
            args: {
                limit: t.arg.int({ defaultValue: 25 }),
                offset: t.arg.int({ defaultValue: 0 }),
                type: t.arg.string(),
                source: t.arg.string(),
                severity: t.arg.string(),
                query: t.arg.string(),
                maliciousOnly: t.arg.boolean({ defaultValue: false }),
                since: t.arg.string(),
            },
            resolve: async (_root, args) => {
                const limit = args.limit ?? 25;
                const offset = args.offset ?? 0;

                // Build dynamic conditions
                // Exclude CVE-type entries — those belong in vulnerabilities, not IOCs
                const conditions: ReturnType<typeof eq>[] = [
                    sql`${iocs.type} != 'cve'` as unknown as ReturnType<typeof eq>,
                ];

                if (args.type) {
                    conditions.push(eq(iocs.type, args.type));
                }
                if (args.source) {
                    conditions.push(eq(iocs.source, args.source));
                }
                if (args.severity) {
                    conditions.push(eq(iocs.severity, args.severity));
                }
                if (args.query) {
                    const searchTerm = `%${args.query}%`;
                    conditions.push(
                        sql`(${iocs.value} ILIKE ${searchTerm} OR ${iocs.type} ILIKE ${searchTerm})`
                    );
                }
                if (args.since) {
                    conditions.push(
                        sql`${iocs.lastSeen} >= ${args.since}` as unknown as ReturnType<typeof eq>
                    );
                }

                // Count query — use and() to combine ALL conditions in a single .where()
                // Note: Drizzle's .where() called multiple times REPLACES (not ANDs).
                const whereClause = conditions.length === 1
                    ? conditions[0]
                    : and(...conditions);

                const [countResult] = await db.select({ count: count() })
                    .from(iocs)
                    .where(whereClause!);
                const total = countResult?.count ?? 0;

                // Data query
                const items = await db.select().from(iocs)
                    .where(whereClause!)
                    .limit(limit)
                    .offset(offset)
                    .orderBy(desc(iocs.lastSeen));

                return {
                    items: items.map(item => ({
                        id: item.id,
                        type: item.type,
                        value: item.value,
                        source: item.source,
                        threatType: item.threatType,
                        severity: item.severity ?? null,
                        confidence: item.confidence ?? null,
                        tags: item.tags ?? null,
                        isMalicious: false,
                        firstSeen: item.firstSeen,
                        lastSeen: item.lastSeen,
                    })),
                    total,
                    hasMore: offset + limit < total,
                };
            },
        }),

        // ── Existing: Vulnerabilities ──
        vulnerabilities: t.field({
            type: 'VulnerabilityConnection',
            args: {
                limit: t.arg.int({ defaultValue: 25 }),
                offset: t.arg.int({ defaultValue: 0 }),
                severity: t.arg.string(),
                kevOnly: t.arg.boolean({ defaultValue: false }),
                query: t.arg.string(),
                since: t.arg.string(),
            },
            resolve: async (_root, args) => {
                const limit = args.limit ?? 25;
                const offset = args.offset ?? 0;

                // Build dynamic conditions
                const conditions = [];

                if (args.severity) {
                    conditions.push(eq(vulnerabilities.severity, args.severity));
                }
                if (args.kevOnly) {
                    conditions.push(eq(vulnerabilities.isExploited, true));
                }
                if (args.query) {
                    const searchTerm = `%${args.query}%`;
                    conditions.push(
                        sql`(${vulnerabilities.cveId} ILIKE ${searchTerm} OR ${vulnerabilities.description} ILIKE ${searchTerm})`
                    );
                }
                if (args.since) {
                    conditions.push(
                        sql`${vulnerabilities.publishedDate} >= ${args.since}` as unknown as ReturnType<typeof eq>
                    );
                }

                // Count query
                let countQuery = db.select({ count: count() }).from(vulnerabilities);
                for (const cond of conditions) {
                    countQuery = countQuery.where(cond) as typeof countQuery;
                }
                const [countResult] = await countQuery;
                const total = countResult?.count ?? 0;

                // Data query
                let dataQuery = db.select().from(vulnerabilities);
                for (const cond of conditions) {
                    dataQuery = dataQuery.where(cond) as typeof dataQuery;
                }
                const items = await dataQuery
                    .limit(limit)
                    .offset(offset)
                    .orderBy(desc(vulnerabilities.publishedDate));

                return {
                    items: items.map(item => ({
                        id: item.id,
                        cveId: item.cveId,
                        description: item.description,
                        severity: item.severity,
                        cvssScore: item.cvssScore ? parseFloat(String(item.cvssScore)) : null,
                        vendor: item.vendorProject ?? null,
                        product: item.product ?? null,
                        isKev: item.isExploited ?? false,
                        publishedDate: item.publishedDate ?? item.createdAt ?? null,
                    })),
                    total,
                    hasMore: offset + limit < total,
                };
            },
        }),

        // ── Upgraded: Polymorphic Search ──
        search: t.field({
            type: [SearchResultType],
            args: {
                query: t.arg.string({ required: true }),
                limit: t.arg.int({ defaultValue: 20 }),
            },
            resolve: async (_root, args) => {
                const searchTerm = `%${args.query}%`;
                const perType = Math.ceil((args.limit ?? 20) / 3);

                // Search actors
                const actors = await db.select()
                    .from(threatActors)
                    .where(sql`${threatActors.name} ILIKE ${searchTerm} OR ${threatActors.description} ILIKE ${searchTerm}`)
                    .limit(perType);

                const actorResults = actors.map(item => ({
                    id: item.id,
                    stixId: item.stixId,
                    name: item.name,
                    aliases: item.aliases ?? [],
                    description: item.description,
                    primaryMotivation: item.primaryMotivation,
                    sophistication: item.sophistication,
                    country: item.country ?? null,
                    firstSeen: item.firstSeen ?? null,
                    lastSeen: item.lastSeen ?? null,
                }));

                // Search IOCs
                const iocItems = await db.select()
                    .from(iocs)
                    .where(sql`${iocs.value} ILIKE ${searchTerm} OR ${iocs.type} ILIKE ${searchTerm}`)
                    .limit(perType);

                const iocResults = iocItems.map(item => ({
                    id: item.id,
                    type: item.type,
                    value: item.value,
                    source: item.source,
                    threatType: item.threatType,
                    severity: item.severity ?? null,
                    confidence: item.confidence ?? null,
                    tags: item.tags ?? null,
                    isMalicious: false,
                    firstSeen: item.firstSeen,
                    lastSeen: item.lastSeen,
                }));

                // Search vulnerabilities
                const vulnItems = await db.select()
                    .from(vulnerabilities)
                    .where(sql`${vulnerabilities.cveId} ILIKE ${searchTerm} OR ${vulnerabilities.description} ILIKE ${searchTerm}`)
                    .limit(perType);

                const vulnResults = vulnItems.map(item => ({
                    id: item.id,
                    cveId: item.cveId,
                    description: item.description,
                    severity: item.severity,
                    cvssScore: item.cvssScore ? parseFloat(String(item.cvssScore)) : null,
                    vendor: item.vendorProject ?? null,
                    product: item.product ?? null,
                    isKev: item.isExploited ?? false,
                    publishedDate: item.publishedDate ?? item.createdAt ?? null,
                }));

                return [...actorResults, ...iocResults, ...vulnResults].slice(0, args.limit ?? 20);
            },
        }),

        // ── Existing: Stats ──
        stats: t.field({
            type: t.builder.objectRef<{
                threatActors: number;
                criticalActors: number;
                techniques: number;
                iocs: number;
                criticalIocs: number;
                vulnerabilities: number;
                criticalVulns: number;
                kevCount: number;
            }>('Stats').implement({
                fields: (st) => ({
                    threatActors: st.exposeInt('threatActors'),
                    criticalActors: st.exposeInt('criticalActors'),
                    techniques: st.exposeInt('techniques'),
                    iocs: st.exposeInt('iocs'),
                    criticalIocs: st.exposeInt('criticalIocs'),
                    vulnerabilities: st.exposeInt('vulnerabilities'),
                    criticalVulns: st.exposeInt('criticalVulns'),
                    kevCount: st.exposeInt('kevCount'),
                }),
            }),
            resolve: async () => {
                const [actorsResult] = await db.select({ count: count() }).from(threatActors);
                const [criticalActorsResult] = await db.select({ count: count() }).from(threatActors)
                    .where(sql`${threatActors.sophistication} IN ('expert', 'advanced')`);
                const [iocsResult] = await db.select({ count: count() }).from(iocs)
                    .where(sql`${iocs.type} != 'cve'`);
                const [criticalResult] = await db.select({ count: count() }).from(iocs)
                    .where(sql`${iocs.severity} = 'critical' AND ${iocs.type} != 'cve'`);
                const [vulnsResult] = await db.select({ count: count() }).from(vulnerabilities);
                const [criticalVulnsResult] = await db.select({ count: count() }).from(vulnerabilities).where(eq(vulnerabilities.severity, 'critical'));
                const [kevResult] = await db.select({ count: count() }).from(vulnerabilities).where(eq(vulnerabilities.isExploited, true));

                let techCount = 0;
                try {
                    const techsResult = await db.execute(sql`SELECT COUNT(*) as count FROM techniques`);
                    const rows = extractRows(techsResult);
                    if (rows[0]) {
                        techCount = Number((rows[0] as Record<string, unknown>).count ?? 0);
                    }
                } catch { /* techniques table may not exist */ }

                return {
                    threatActors: actorsResult?.count ?? 0,
                    criticalActors: criticalActorsResult?.count ?? 0,
                    techniques: techCount,
                    iocs: iocsResult?.count ?? 0,
                    criticalIocs: criticalResult?.count ?? 0,
                    vulnerabilities: vulnsResult?.count ?? 0,
                    criticalVulns: criticalVulnsResult?.count ?? 0,
                    kevCount: kevResult?.count ?? 0,
                };
            },
        }),

        // ==================================================================
        // Sightings Queries (migrated from REST)
        // ==================================================================

        // ── Paginated Sightings Feed ──
        sightings: t.field({
            type: 'SightingConnection',
            args: {
                limit: t.arg.int({ defaultValue: 50 }),
                offset: t.arg.int({ defaultValue: 0 }),
                source: t.arg.string(),
                iocType: t.arg.string(),
                since: t.arg.string(),
            },
            resolve: async (_root, args) => {
                const limit = args.limit ?? 50;
                const offset = args.offset ?? 0;

                // Count
                const conditions = [];
                if (args.source) conditions.push(eq(sightings.source, args.source));
                if (args.since) {
                    conditions.push(
                        sql`${sightings.observedAt} >= ${args.since}` as unknown as ReturnType<typeof eq>
                    );
                }

                let countQuery = db.select({ count: count() }).from(sightings);
                for (const cond of conditions) {
                    countQuery = countQuery.where(cond) as typeof countQuery;
                }
                const [countResult] = await countQuery;
                const total = countResult?.count ?? 0;

                // Data — join with IOCs for value/type
                let dataQuery = db.select({
                    sighting: sightings,
                    iocValue: iocs.value,
                    iocType: iocs.type,
                })
                    .from(sightings)
                    .leftJoin(iocs, eq(sightings.iocId, iocs.id));

                for (const cond of conditions) {
                    dataQuery = dataQuery.where(cond) as typeof dataQuery;
                }

                // Filter by IOC type (post-join)
                if (args.iocType) {
                    dataQuery = dataQuery.where(eq(iocs.type, args.iocType)) as typeof dataQuery;
                }

                const rows = await dataQuery
                    .orderBy(desc(sightings.observedAt))
                    .limit(limit)
                    .offset(offset);

                return {
                    items: rows.map(row => ({
                        id: row.sighting.id,
                        iocId: row.sighting.iocId,
                        iocValue: row.iocValue || 'unknown',
                        iocType: row.iocType || 'unknown',
                        type: row.sighting.type,
                        source: row.sighting.source,
                        description: row.sighting.description,
                        confidence: row.sighting.confidence ?? 50,
                        count: row.sighting.count ?? 1,
                        observedAt: row.sighting.observedAt,
                        createdAt: row.sighting.createdAt,
                    })),
                    total,
                    hasMore: offset + limit < total,
                };
            },
        }),

        // ── Sighting Stats (aggregates) ──
        sightingStats: t.field({
            type: 'SightingStats',
            resolve: async () => {
                // Total count
                const [totalResult] = await db.select({ count: count() }).from(sightings);
                const totalSightings = totalResult?.count ?? 0;

                // Average confidence
                const [avgResult] = await db.select({
                    avg: sql<number>`round(avg(${sightings.confidence}))::int`,
                }).from(sightings);
                const avgConfidence = avgResult?.avg ?? 0;

                // Top IOCs by observation count (join with iocs table)
                const topIOCRows = await db.select({
                    iocValue: iocs.value,
                    count: sql<number>`count(*)::int`,
                })
                    .from(sightings)
                    .leftJoin(iocs, eq(sightings.iocId, iocs.id))
                    .groupBy(iocs.value)
                    .orderBy(sql`count(*) DESC`)
                    .limit(10);

                // By source
                const sourceRows = await db.select({
                    source: sightings.source,
                    count: sql<number>`count(*)::int`,
                })
                    .from(sightings)
                    .groupBy(sightings.source)
                    .orderBy(sql`count(*) DESC`)
                    .limit(20);

                return {
                    totalSightings,
                    avgConfidence,
                    topIOCs: topIOCRows.map(r => ({ iocValue: r.iocValue || 'unknown', count: r.count })),
                    bySource: sourceRows.map(r => ({ source: r.source, count: r.count })),
                };
            },
        }),

        // ==================================================================
        // NEW: Neo4j Graph Exploration Queries
        // ==================================================================

        // ── Graph Search (fuzzy CONTAINS match in Neo4j) ──
        graphSearch: t.field({
            type: 'GraphResultGQL',
            args: {
                query: t.arg.string({ required: true }),
                limit: t.arg.int({ defaultValue: 50 }),
            },
            resolve: async (_root, args) => {
                const result = await graphSearch(args.query, args.limit ?? 50);
                return { nodes: result.nodes, edges: result.edges };
            },
        }),

        // ── Neighborhood Expand (N hops from any node) ──
        graphExplore: t.field({
            type: 'GraphResultGQL',
            args: {
                nodeId: t.arg.string({ required: true }),
                depth: t.arg.int({ defaultValue: 1 }),
                limit: t.arg.int({ defaultValue: 100 }),
            },
            resolve: async (_root, args) => {
                const result = await neighborhoodExpand(args.nodeId, args.depth ?? 1, args.limit ?? 100);
                return { nodes: result.nodes, edges: result.edges };
            },
        }),

        // ── Shortest Path between two entities ──
        graphShortestPath: t.field({
            type: 'GraphResultGQL',
            args: {
                fromId: t.arg.string({ required: true }),
                toId: t.arg.string({ required: true }),
                maxDepth: t.arg.int({ defaultValue: 6 }),
            },
            resolve: async (_root, args) => {
                const result = await findShortestPath(args.fromId, args.toId, args.maxDepth ?? 6);
                return { nodes: result.nodes, edges: result.edges };
            },
        }),

        // ── Attack Tree (Actor → Techniques → Tactics) ──
        attackTree: t.field({
            type: 'GraphResultGQL',
            args: {
                actorName: t.arg.string({ required: true }),
            },
            resolve: async (_root, args) => {
                const result = await getAttackTree(args.actorName);
                return { nodes: result.nodes, edges: result.edges };
            },
        }),

        // ── IOC Pivot (IOC → Pulse → Actor → other IOCs) ──
        iocPivot: t.field({
            type: 'GraphResultGQL',
            args: {
                iocValue: t.arg.string({ required: true }),
                limit: t.arg.int({ defaultValue: 50 }),
            },
            resolve: async (_root, args) => {
                const result = await iocPivot(args.iocValue, args.limit ?? 50);
                return { nodes: result.nodes, edges: result.edges };
            },
        }),
    }),
});

// Build the schema
export const schema = builder.toSchema();
