/**
 * Neo4j Sync — Telco entities (B1.2).
 *
 * Batch-MERGE the three telco tables into Neo4j nodes so that telco
 * relationships (inserted via /v1/relationships) can hydrate into edges —
 * autoHydrateRelationship() MATCHes pre-existing nodes, it does not create
 * them, so this sync is the prerequisite for telco graph participation.
 *
 * Node identity: keyed on `refId` (the natural key; stix_id is nullable for
 * telco). We also set `id = refId` so the hydrate's MATCH
 * (`WHERE src.id = $srcId`) resolves when relationships reference a telco
 * entity by its refId. `pgId` is kept for joins back to Postgres.
 *
 * Mirrors syncEntities/actorSync.ts.
 */

import { db } from '@rinjani/db';
import { networkElements, signalingInterfaces, fraudSchemes } from '@rinjani/db/schema';
import type { NetworkElement, SignalingInterface, FraudScheme } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

// ── Pure node mappers (exported for unit tests) ─────────────────────────────

export function toNetworkElementNode(r: NetworkElement) {
    return {
        refId: r.refId,
        id: r.refId,                 // MATCH key for autoHydrate (src.id = $srcId)
        pgId: r.id,
        name: r.name,
        elementType: r.elementType,
        architectureSegment: r.architectureSegment ?? 'unknown',
        vendor: r.vendor ?? [],
        description: (r.description ?? '').slice(0, 500),
    };
}

export function toSignalingInterfaceNode(r: SignalingInterface) {
    return {
        refId: r.refId,
        id: r.refId,
        pgId: r.id,
        name: r.name,
        protocol: r.protocol,
        referencePoint: r.referencePoint ?? '',
        specRef: r.specRef ?? '',
        description: (r.description ?? '').slice(0, 500),
    };
}

export function toFraudSchemeNode(r: FraudScheme) {
    return {
        refId: r.refId,
        id: r.refId,
        pgId: r.id,
        name: r.name,
        schemeType: r.schemeType,
        monetization: (r.monetization ?? '').slice(0, 500),
        gsmaFsCategories: r.gsmaFsCategories ?? [],
        threeGppThreats: r.threeGppThreats ?? [],
        description: (r.description ?? '').slice(0, 500),
    };
}

// ── Sync functions ──────────────────────────────────────────────────────────

export async function syncNetworkElements(onProgress?: (pct: number) => void): Promise<number> {
    const rows = await db.select().from(networkElements);
    if (rows.length === 0) return 0;
    const batch = rows.map(toNetworkElementNode);
    const session = getNeo4jDriver().session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (n:NetworkElement {refId: row.refId})
            SET n.id = row.id, n.pgId = row.pgId, n.name = row.name,
                n.elementType = row.elementType, n.architectureSegment = row.architectureSegment,
                n.vendor = row.vendor, n.description = row.description,
                n.syncedAt = datetime()
        `, { batch });
        onProgress?.(100);
        log.info('Network elements synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}

export async function syncSignalingInterfaces(onProgress?: (pct: number) => void): Promise<number> {
    const rows = await db.select().from(signalingInterfaces);
    if (rows.length === 0) return 0;
    const batch = rows.map(toSignalingInterfaceNode);
    const session = getNeo4jDriver().session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (n:SignalingInterface {refId: row.refId})
            SET n.id = row.id, n.pgId = row.pgId, n.name = row.name,
                n.protocol = row.protocol, n.referencePoint = row.referencePoint,
                n.specRef = row.specRef, n.description = row.description,
                n.syncedAt = datetime()
        `, { batch });
        onProgress?.(100);
        log.info('Signaling interfaces synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}

export async function syncFraudSchemes(onProgress?: (pct: number) => void): Promise<number> {
    const rows = await db.select().from(fraudSchemes);
    if (rows.length === 0) return 0;
    const batch = rows.map(toFraudSchemeNode);
    const session = getNeo4jDriver().session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (n:FraudScheme {refId: row.refId})
            SET n.id = row.id, n.pgId = row.pgId, n.name = row.name,
                n.schemeType = row.schemeType, n.monetization = row.monetization,
                n.gsmaFsCategories = row.gsmaFsCategories, n.threeGppThreats = row.threeGppThreats,
                n.description = row.description,
                n.syncedAt = datetime()
        `, { batch });
        onProgress?.(100);
        log.info('Fraud schemes synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}

/** Sync all three telco entity types. Returns per-type counts. */
export async function syncTelco(onProgress?: (pct: number) => void): Promise<{
    networkElements: number;
    signalingInterfaces: number;
    fraudSchemes: number;
}> {
    const ne = await syncNetworkElements();
    onProgress?.(33);
    const si = await syncSignalingInterfaces();
    onProgress?.(66);
    const fs = await syncFraudSchemes();
    onProgress?.(100);
    return { networkElements: ne, signalingInterfaces: si, fraudSchemes: fs };
}
