/**
 * Neo4j Sync — MITRE FiGHT (5G/telco) + ATLAS (AI) technique nodes (FW.1).
 *
 * THE DIFFERENTIATOR. Every CTI platform sources MITRE ATT&CK; few put FiGHT
 * (5G threats) and ATLAS (AI-system threats) into the SAME graph as the
 * telco-fraud + on-chain layers, so the agent can hunt across all of them in
 * one Cypher query (e.g. 5G fraud technique → fraud scheme → signaling
 * interface → cashout wallet → Arkham entity).
 *
 * Mirrors telcoSync/onchainSync: batch-MERGE technique nodes keyed on their
 * natural id (FiGHT fightId "FGT5004", ATLAS atlasId "AML.T0043"), with
 * node.id = that id so autoHydrateRelationship's MATCH resolves when a
 * relationship references a technique (e.g. fraud_scheme -[uses]-> fight_technique).
 */

import { db } from '@rinjani/db';
import { fightTechniques, atlasTechniques } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

type FightTechnique = typeof fightTechniques.$inferSelect;
type AtlasTechnique = typeof atlasTechniques.$inferSelect;

// ── Pure node mappers (exported for unit tests) ─────────────────────────────

export function toFightTechniqueNode(r: FightTechnique) {
    return {
        fightId: r.fightId,
        id: r.fightId,                  // MATCH key for autoHydrate (tgt.id = $tgtId)
        pgId: r.id,
        name: r.name,
        status: r.status ?? '',                          // theoretical | PoC | observed
        architectureSegment: r.architectureSegment ?? '', // RAN | Core | UE | OA&M
        tacticIds: r.tacticIds ?? [],
        platforms: r.platforms ?? [],
        description: (r.description ?? '').slice(0, 500),
    };
}

export function toAtlasTechniqueNode(r: AtlasTechnique) {
    return {
        atlasId: r.atlasId,
        id: r.atlasId,                  // MATCH key for autoHydrate
        pgId: r.id,
        name: r.name,
        maturity: r.maturity ?? '',                       // demonstrated | feasible | theoretical
        tacticIds: r.tacticIds ?? [],
        attackReferenceId: r.attackReferenceId ?? '',     // ATT&CK cross-ref, e.g. T1596
        description: (r.description ?? '').slice(0, 500),
    };
}

export async function syncFightTechniques(): Promise<number> {
    const rows = await db.select().from(fightTechniques);
    if (rows.length === 0) return 0;
    const batch = rows.map(toFightTechniqueNode);
    const session = getNeo4jDriver().session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (n:FightTechnique {fightId: row.fightId})
            SET n.id = row.id, n.pgId = row.pgId, n.name = row.name,
                n.status = row.status, n.architectureSegment = row.architectureSegment,
                n.tacticIds = row.tacticIds, n.platforms = row.platforms,
                n.description = row.description, n.syncedAt = datetime()
        `, { batch });
        log.info('FiGHT techniques synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}

export async function syncAtlasTechniques(): Promise<number> {
    const rows = await db.select().from(atlasTechniques);
    if (rows.length === 0) return 0;
    const batch = rows.map(toAtlasTechniqueNode);
    const session = getNeo4jDriver().session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (n:AtlasTechnique {atlasId: row.atlasId})
            SET n.id = row.id, n.pgId = row.pgId, n.name = row.name,
                n.maturity = row.maturity, n.tacticIds = row.tacticIds,
                n.attackReferenceId = row.attackReferenceId,
                n.description = row.description, n.syncedAt = datetime()
        `, { batch });
        log.info('ATLAS techniques synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}

export async function syncFrameworks(): Promise<{ fightTechniques: number; atlasTechniques: number }> {
    return {
        fightTechniques: await syncFightTechniques(),
        atlasTechniques: await syncAtlasTechniques(),
    };
}
