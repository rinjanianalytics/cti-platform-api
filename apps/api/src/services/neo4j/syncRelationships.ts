/**
 * Neo4j Relationship Sync — MITRE ATT&CK USES edges
 *
 * Resolves STIX UUIDs to MITRE IDs and creates USES edges in Neo4j.
 */

import { db, sql } from '@rinjani/db';
import { mitreRelationships } from '@rinjani/db/schema';
import { getNeo4jDriver } from './driver';
import { createLogger } from '../../lib/logger';

const log = createLogger('Neo4j');

export async function syncRelationships(): Promise<number> {
    // The relationships table stores full STIX 2.x IDs (e.g. "intrusion-set--<uuid>")
    // while entity tables use short MITRE IDs (e.g. "mitre--G0007", "T1059").
    // We resolve the mapping by extracting MITRE IDs from relationship descriptions
    // which contain markdown links like [Name](https://attack.mitre.org/groups/G0094).

    // Step 1: Build STIX UUID → MITRE ID mapping
    // The MITRE ATT&CK STIX bundle is the authoritative source for UUID→ID mapping.
    // We fetch it and extract external_references for all entity types.
    const ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

    const actorLookup = new Map<string, string>();
    const techLookup = new Map<string, string>();
    const malwareLookup = new Map<string, string>();
    const toolLookup = new Map<string, string>();

    try {
        log.info('Fetching MITRE ATT&CK STIX bundle for UUID mapping');
        const resp = await fetch(ATTACK_URL);
        if (!resp.ok) throw new Error(`STIX fetch failed: ${resp.status}`);
        const bundle = await resp.json() as { objects: Array<{ type: string; id: string; external_references?: Array<{ source_name: string; external_id?: string }> }> };

        for (const obj of bundle.objects) {
            const ref = obj.external_references?.find((r: { source_name: string; external_id?: string }) => r.source_name === 'mitre-attack');
            const mitreId = ref?.external_id;
            if (!mitreId) continue;

            switch (obj.type) {
                case 'intrusion-set': actorLookup.set(obj.id, mitreId); break;  // G0094
                case 'attack-pattern': techLookup.set(obj.id, mitreId); break;  // T1059, T1059.001
                case 'malware': malwareLookup.set(obj.id, mitreId); break;      // S0139
                case 'tool': toolLookup.set(obj.id, mitreId); break;            // S0154
            }
        }
        log.info('STIX bundle mapped', { actors: actorLookup.size, techniques: techLookup.size, malware: malwareLookup.size, tools: toolLookup.size });
    } catch (stixErr) {
        // Fallback: use description-based regex if STIX fetch fails
        log.warn('STIX bundle fetch failed, falling back to description regex', { error: stixErr });

        const actorMapping = await db.execute(sql`
            SELECT DISTINCT source_id as stix_uuid,
                substring(description from 'groups/(G[0-9]+)') as mitre_id
            FROM relationships
            WHERE source_type = 'intrusion-set' AND description LIKE '%groups/G%'
        `);
        for (const r of actorMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) actorLookup.set(String(r.stix_uuid), String(r.mitre_id)); }

        const techMapping = await db.execute(sql`
            SELECT DISTINCT target_id as stix_uuid,
                substring(description from 'techniques/(T[0-9]+\\.?[0-9]*)') as mitre_id
            FROM relationships
            WHERE target_type = 'attack-pattern' AND description LIKE '%techniques/T%'
        `);
        for (const r of techMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) techLookup.set(String(r.stix_uuid), String(r.mitre_id)); }

        const malwareMapping = await db.execute(sql`
            SELECT DISTINCT target_id as stix_uuid,
                substring(description from 'software/(S[0-9]+)') as mitre_id
            FROM relationships
            WHERE target_type = 'malware' AND description LIKE '%software/S%'
        `);
        for (const r of malwareMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) malwareLookup.set(String(r.stix_uuid), String(r.mitre_id)); }

        const toolMapping = await db.execute(sql`
            SELECT DISTINCT source_id as stix_uuid,
                substring(description from 'software/(S[0-9]+)') as mitre_id
            FROM relationships
            WHERE source_type = 'tool' AND description LIKE '%software/S%'
        `);
        for (const r of toolMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) toolLookup.set(String(r.stix_uuid), String(r.mitre_id)); }
    }

    log.info('STIX-MITRE mappings', { actors: actorLookup.size, techniques: techLookup.size, malware: malwareLookup.size, tools: toolLookup.size });

    // Step 2: Get all USES relationships and resolve both sides
    const allRels = await db.select({
        sourceType: mitreRelationships.sourceType,
        sourceId: mitreRelationships.sourceId,
        targetType: mitreRelationships.targetType,
        targetId: mitreRelationships.targetId,
        description: mitreRelationships.description,
    }).from(mitreRelationships)
        .where(sql`${mitreRelationships.relationshipType} = 'uses'`);

    if (allRels.length === 0) return 0;

    // Resolve STIX UUIDs to MITRE IDs using our lookup maps
    const lookupMap: Record<string, Map<string, string>> = {
        'intrusion-set': actorLookup,
        'attack-pattern': techLookup,
        'malware': malwareLookup,
        'tool': toolLookup,
    };

    const labelMap: Record<string, string> = {
        'intrusion-set': 'Actor',
        'attack-pattern': 'Technique',
        'malware': 'Malware',
        'tool': 'Tool',
    };

    // Group resolved edges by source_label|target_label
    const edgeGroups = new Map<string, Array<{ srcId: string; tgtId: string; desc: string }>>();
    let skipped = 0;

    for (const rel of allRels) {
        const srcLookup = lookupMap[rel.sourceType];
        const tgtLookup = lookupMap[rel.targetType];
        const srcLabel = labelMap[rel.sourceType];
        const tgtLabel = labelMap[rel.targetType];

        if (!srcLookup || !tgtLookup || !srcLabel || !tgtLabel) { skipped++; continue; }

        const resolvedSrc = srcLookup.get(rel.sourceId);
        const resolvedTgt = tgtLookup.get(rel.targetId);

        if (!resolvedSrc || !resolvedTgt) { skipped++; continue; }

        const groupKey = `${srcLabel}|${tgtLabel}`;
        if (!edgeGroups.has(groupKey)) edgeGroups.set(groupKey, []);
        edgeGroups.get(groupKey)!.push({
            srcId: resolvedSrc,
            tgtId: resolvedTgt,
            desc: (rel.description || '').slice(0, 300),
        });
    }

    log.info('Relationship resolution done', { resolved: allRels.length - skipped, skipped });

    // Step 3: Create USES edges in Neo4j
    const driver = getNeo4jDriver();
    const session = driver.session();
    let created = 0;

    try {
        for (const [groupKey, edges] of Array.from(edgeGroups.entries())) {
            const [srcLabel, tgtLabel] = groupKey.split('|');
            const BATCH = 500;

            for (let i = 0; i < edges.length; i += BATCH) {
                const batch = edges.slice(i, i + BATCH);
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (src:${srcLabel} {mitreId: row.srcId})
                    MATCH (tgt:${tgtLabel} {mitreId: row.tgtId})
                    MERGE (src)-[r:USES]->(tgt)
                    SET r.description = coalesce(row.desc, ''),
                        r.syncedAt = datetime()
                `, { batch });
                created += batch.length;
            }

            log.info('USES edges created', { count: edges.length, from: srcLabel, to: tgtLabel });
        }

        log.info('Total relationship edges created', { count: created });
        return created;
    } finally {
        await session.close();
    }
}

/**
 * Re-hydrate EVERY non-USES graph-participating relationship edge from the
 * relational source of truth.
 *
 * The specialised `syncRelationships()` above owns USES — it resolves STIX
 * UUID→MITRE ID, which the generic matcher below can't do. This pass covers
 * everything else: telco edges (EXPLOITS_VIA, USES_INTERFACE, ENABLES_FRAUD,
 * CONNECTS_TO) and STIX SDO links (ATTRIBUTED_TO, INDICATES, MITIGATES, …).
 *
 * WHY THIS EXISTS: before it, those edges only ever hydrated at row-INSERT
 * time via `autoHydrateRelationship`. A full graph rebuild (or a relationship
 * row created BEFORE its endpoint nodes were synced) silently produced NO
 * edge, and no full sync ever recovered it — Neo4j was not reconstructible
 * from Postgres for any non-USES edge. The orchestrator comment "telco nodes
 * must exist before syncRelationships() so telco edges can hydrate" assumed a
 * pass like this; it didn't exist until now.
 *
 * Matches endpoints by mitreId|id|uuid (same matcher as
 * `autoHydrateRelationship`), batched per (srcLabel, tgtLabel, edge). Rows
 * whose endpoints don't resolve (e.g. a node not yet synced) are MATCH-skipped
 * by Cypher, not errored. Idempotent (MERGE). Returns edges actually created.
 */
export async function syncGenericRelationships(): Promise<number> {
    const rows = await db.select({
        sourceType: mitreRelationships.sourceType,
        sourceId: mitreRelationships.sourceId,
        relationshipType: mitreRelationships.relationshipType,
        targetType: mitreRelationships.targetType,
        targetId: mitreRelationships.targetId,
        description: mitreRelationships.description,
        confidence: mitreRelationships.confidence,
    }).from(mitreRelationships)
        .where(sql`${mitreRelationships.relationshipType} <> 'uses'`);

    if (rows.length === 0) return 0;

    // Group by srcLabel|tgtLabel|edge — labels and rel-types can't be
    // parameterised in Cypher, and they come from the closed allowlist
    // (labelForEntityType / cypherEdgeLabel), so interpolation is safe.
    const groups = new Map<string, Array<{ srcId: string; tgtId: string; desc: string; confidence: number | null }>>();
    let skipped = 0;
    for (const r of rows) {
        const srcLabel = labelForEntityType(r.sourceType);
        const tgtLabel = labelForEntityType(r.targetType);
        if (!srcLabel || !tgtLabel) { skipped++; continue; }
        const key = `${srcLabel}|${tgtLabel}|${cypherEdgeLabel(r.relationshipType)}`;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key)!.push({
            srcId: r.sourceId,
            tgtId: r.targetId,
            desc: (r.description || '').slice(0, 300),
            confidence: r.confidence ?? null,
        });
    }

    let driver;
    try {
        driver = getNeo4jDriver();
    } catch (err) {
        log.warn('syncGenericRelationships skipped — Neo4j driver unavailable', { error: (err as Error).message });
        return 0;
    }

    const session = driver.session();
    let created = 0;
    try {
        for (const [key, edges] of Array.from(groups.entries())) {
            const [srcLabel, tgtLabel, edge] = key.split('|');
            const BATCH = 500;
            for (let i = 0; i < edges.length; i += BATCH) {
                const batch = edges.slice(i, i + BATCH);
                const res = await session.run(`
                    UNWIND $batch AS row
                    MATCH (src:${srcLabel}) WHERE src.mitreId = row.srcId OR src.id = row.srcId OR src.uuid = row.srcId
                    MATCH (tgt:${tgtLabel}) WHERE tgt.mitreId = row.tgtId OR tgt.id = row.tgtId OR tgt.uuid = row.tgtId
                    MERGE (src)-[r:${edge}]->(tgt)
                    SET r.description = coalesce(row.desc, ''),
                        r.confidence = row.confidence,
                        r.syncedAt = datetime()
                `, { batch });
                created += res.summary.counters.updates().relationshipsCreated;
            }
            log.info('Generic edges hydrated', { group: key, rows: edges.length });
        }
        log.info('Generic relationship hydration done', { created, groups: groups.size, skipped });
        return created;
    } finally {
        await session.close();
    }
}

// ============================================================================
// Auto-hydrate hook — single-relationship side-effect on INSERT
// ============================================================================

/**
 * Map our relational `source_type` / `target_type` strings to the Neo4j node
 * labels we maintain in `syncAll`. STIX-style hyphenated forms come from the
 * STIX importer; underscore forms come from the user-facing /v1/relationships
 * route. Both are normalised here.
 */
const NEO4J_LABEL_BY_ENTITY: Record<string, string> = {
    'threat-actor': 'Actor',
    'threat_actor': 'Actor',
    'intrusion-set': 'Actor',
    'attack-pattern': 'Technique',
    technique: 'Technique',
    malware: 'Malware',
    tool: 'Tool',
    vulnerability: 'Vulnerability',
    cve: 'Vulnerability',
    ioc: 'IOC',
    indicator: 'IOC',
    campaign: 'Campaign',
    'course-of-action': 'Mitigation',
    mitigation: 'Mitigation',
    infrastructure: 'Infrastructure',
    // Telco vertical (B1.2). Both hyphen (route) + underscore (table) forms.
    // Nodes are created by telcoSync (services/neo4j/syncEntities/telcoSync.ts);
    // edges hydrate here once both endpoint nodes exist.
    'network-element': 'NetworkElement',
    'network_element': 'NetworkElement',
    'signaling-interface': 'SignalingInterface',
    'signaling_interface': 'SignalingInterface',
    'fraud-scheme': 'FraudScheme',
    'fraud_scheme': 'FraudScheme',
    // On-chain / follow-the-money (AA.6.2). Nodes created by onchainSync.
    wallet: 'Wallet',
    // MITRE FiGHT (5G/telco) + ATLAS (AI) techniques (FW.1). Nodes created by
    // frameworkSync — so the fraud_scheme → fight_technique bridge (and any
    // actor → technique link) now hydrates into the unified graph.
    'fight-technique': 'FightTechnique',
    'fight_technique': 'FightTechnique',
    'atlas-technique': 'AtlasTechnique',
    'atlas_technique': 'AtlasTechnique',
};

/**
 * Resolve a relationship entity-type (hyphen or underscore form) to its Neo4j
 * node label, or null if the type isn't graph-participating. Exported so the
 * label map can be unit-tested directly — a missing telco entry is the silent
 * "edge never hydrates" trap, so this is worth a boundary test.
 */
export function labelForEntityType(entityType: string): string | null {
    return NEO4J_LABEL_BY_ENTITY[entityType.toLowerCase()] ?? null;
}

/**
 * Map our `relationship_type` string to the Cypher edge label we want.
 * Cypher rel-types can't contain hyphens, so kebab-case becomes
 * SCREAMING_SNAKE. Unknown types fall back to RELATED_TO (the STIX 2.1
 * generic).
 */
function cypherEdgeLabel(relationshipType: string): string {
    return relationshipType.toUpperCase().replace(/-/g, '_');
}

export interface AutoHydrateRow {
    sourceType: string;
    sourceId: string;
    relationshipType: string;
    targetType: string;
    targetId: string;
    description?: string | null;
    confidence?: number | null;
}

/**
 * Side-effect for "we just wrote a row into the relationships table".
 * Looks up matching Neo4j nodes by `mitreId`-or-id, then MERGEs the typed
 * edge. Failures are logged and swallowed — Neo4j MUST NOT be on the
 * critical path of the API write.
 *
 * Idempotent (MERGE).
 */
export async function autoHydrateRelationship(row: AutoHydrateRow): Promise<void> {
    const srcLabel = NEO4J_LABEL_BY_ENTITY[row.sourceType.toLowerCase()];
    const tgtLabel = NEO4J_LABEL_BY_ENTITY[row.targetType.toLowerCase()];
    if (!srcLabel || !tgtLabel) {
        log.debug('autoHydrate skipped — unknown label', { sourceType: row.sourceType, targetType: row.targetType });
        return;
    }

    let driver;
    try {
        driver = getNeo4jDriver();
    } catch (err) {
        log.debug('autoHydrate skipped — Neo4j driver unavailable', { error: (err as Error).message });
        return;
    }

    const session = driver.session();
    try {
        const edge = cypherEdgeLabel(row.relationshipType);
        // Match either by mitreId (G0094, T1059, S0139) or by uuid/string id.
        // Cypher labels can't be parameterised; the labels + edge name come
        // from a closed allowlist above, so string interpolation is safe.
        await session.run(`
            MATCH (src:${srcLabel}) WHERE src.mitreId = $srcId OR src.id = $srcId OR src.uuid = $srcId
            MATCH (tgt:${tgtLabel}) WHERE tgt.mitreId = $tgtId OR tgt.id = $tgtId OR tgt.uuid = $tgtId
            MERGE (src)-[r:${edge}]->(tgt)
            SET r.description = coalesce($desc, ''),
                r.confidence = $confidence,
                r.syncedAt = datetime()
        `, {
            srcId: row.sourceId,
            tgtId: row.targetId,
            desc: row.description ?? null,
            confidence: row.confidence ?? null,
        });
    } catch (err) {
        log.warn('autoHydrate Neo4j upsert failed', { error: (err as Error).message, srcLabel, tgtLabel, rel: row.relationshipType });
    } finally {
        await session.close();
    }
}
