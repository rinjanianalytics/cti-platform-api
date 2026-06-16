/**
 * Neo4j Sync — On-chain wallets (AA.6.2 / Phase 8).
 *
 * Batch-MERGE the wallets table into Neo4j `Wallet` nodes so fund-flow
 * relationships (inserted via /v1/relationships) can hydrate into edges —
 * autoHydrateRelationship() MATCHes pre-existing nodes by `id`, so this sync is
 * the prerequisite for a wallet's graph participation. Mirrors telcoSync.ts.
 *
 * Node identity: keyed on `refId` ("<chain>:<address>"), with `id = refId` so
 * the hydrate's `WHERE src.id = $srcId` resolves. Attribution fields
 * (entityLabel/entityType/confidence) carry onto the node so the graph stays
 * confidence-weighted — a label on a node is still a claim, never a fact.
 */

import { db } from '@rinjani/db';
import { wallets } from '@rinjani/db/schema';
import type { Wallet } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

export function toWalletNode(r: Wallet) {
    return {
        refId: r.refId,
        id: r.refId,                 // MATCH key for autoHydrate (src.id = $srcId)
        pgId: r.id,
        address: r.address,
        chain: r.chain,
        name: (r.name ?? '').slice(0, 500),
        entityLabel: r.entityLabel ?? '',
        entityType: r.entityType ?? '',
        confidence: r.confidence,
        attributionSource: r.attributionSource ?? '',
        riskTags: r.riskTags ?? [],
        description: (r.description ?? '').slice(0, 500),
    };
}

export async function syncWallets(onProgress?: (pct: number) => void): Promise<number> {
    const rows = await db.select().from(wallets);
    if (rows.length === 0) return 0;
    const batch = rows.map(toWalletNode);
    const session = getNeo4jDriver().session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (n:Wallet {refId: row.refId})
            SET n.id = row.id, n.pgId = row.pgId, n.address = row.address,
                n.chain = row.chain, n.name = row.name,
                n.entityLabel = row.entityLabel, n.entityType = row.entityType,
                n.confidence = row.confidence, n.attributionSource = row.attributionSource,
                n.riskTags = row.riskTags, n.description = row.description,
                n.syncedAt = datetime()
        `, { batch });
        onProgress?.(100);
        log.info('Wallets synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}
