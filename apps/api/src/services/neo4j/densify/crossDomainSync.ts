/**
 * Neo4j Cross-Domain Densification
 *
 * Derives cross-domain edges from nodes already in the graph so a "pivot into
 * graph" lands on a real neighbourhood instead of an island. Two deterministic,
 * idempotent passes — graph-internal only (no Postgres reads, no fuzzy matching):
 *
 *   1. REFERS_TO  (IOC → Wallet) — the same crypto address present in both
 *      planes. The OFAC sanctioned-crypto feed is dual-sink (iocs + wallets), so
 *      a sanctioned address exists as BOTH an IOC node and an attributed Wallet
 *      node; this edge bridges threat-intel ↔ on-chain attribution. Pivoting a
 *      sanctioned address now surfaces its Wallet (entityLabel/entityType).
 *
 *   2. ATTRIBUTED_TO (IOC → Actor) — materialises the 1-hop actor attribution
 *      that today exists only transitively via IOC→Pulse→Actor, so neighbourhood
 *      (expand) and related-entity queries reach the actor directly.
 *
 * Both use MERGE — safe to re-run, additive only. Runs as the last step of the
 * full sync (after Pulse/IOC + Wallet nodes exist) and as a standalone
 * `densify` job. Mirrors the batch-Cypher style of syncRelationships.ts.
 */

import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

export interface DensifyResult {
    iocWalletEdges: number;
    iocActorEdges: number;
}

export async function densifyCrossDomain(
    onProgress?: (pct: number) => void,
): Promise<DensifyResult> {
    const session = getNeo4jDriver().session();
    try {
        // 1. IOC ↔ Wallet by shared crypto address. Driven by Wallet (the smaller
        //    set) and matched against the IOC.value index (see ensureNeo4jConstraints).
        const refers = await session.run(`
            MATCH (w:Wallet)
            WHERE w.address IS NOT NULL AND w.address <> ''
            MATCH (i:IOC { value: w.address })
            MERGE (i)-[r:REFERS_TO]->(w)
            SET r.match = 'exact-address', r.syncedAt = datetime()
        `);
        const iocWalletEdges = refers.summary.counters.updates().relationshipsCreated;
        onProgress?.(50);

        // 2. IOC → Actor direct attribution, derived from the existing
        //    IOC→Pulse→Actor path. MERGE de-dupes; re-running is a no-op.
        const attr = await session.run(`
            MATCH (i:IOC)-[:FOUND_IN]->(:Pulse)-[:ATTRIBUTED_TO]->(a:Actor)
            MERGE (i)-[r:ATTRIBUTED_TO]->(a)
            SET r.via = 'pulse', r.syncedAt = datetime()
        `);
        const iocActorEdges = attr.summary.counters.updates().relationshipsCreated;
        onProgress?.(100);

        log.info('Cross-domain densify done', { iocWalletEdges, iocActorEdges });
        return { iocWalletEdges, iocActorEdges };
    } finally {
        await session.close();
    }
}
