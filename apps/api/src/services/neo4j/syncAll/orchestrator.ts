/**
 * Neo4j Full Sync Orchestrator
 *
 * Coordinates all sync operations in dependency order.
 */

import { getNeo4jDriver, ensureNeo4jConstraints } from '../driver';
import neo4j from 'neo4j-driver';
import { syncActors, syncTactics, syncTechniques, syncMalware, syncTools } from '../syncEntities';
import { syncRelationships } from '../syncRelationships';
import { syncPulsesAndIOCs, syncAllIOCs, syncCVEs, syncSimilarIOCs } from '../syncIOCs';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

export interface Neo4jSyncResult {
    actors: number;
    tactics: number;
    techniques: number;
    malware: number;
    tools: number;
    relationships: number;
    pulses: number;
    iocs: number;
    cves: number;
    totalNodes: number;
    totalEdges: number;
    durationMs: number;
}

export async function syncAllToNeo4j(
    onProgress?: (pct: number) => void,
): Promise<Neo4jSyncResult> {
    const start = Date.now();
    log.info('Starting full PG to Neo4j sync');

    await ensureNeo4jConstraints();
    onProgress?.(5);

    const actorCount = await syncActors();
    onProgress?.(15);

    const tacticCount = await syncTactics();
    onProgress?.(25);

    const techCount = await syncTechniques();
    onProgress?.(40);

    const malwareCount = await syncMalware();
    onProgress?.(50);

    const toolCount = await syncTools();
    onProgress?.(60);

    const relCount = await syncRelationships();
    onProgress?.(75);

    const { pulses: pulseCount, iocs: iocCount, links: linkCount } = await syncPulsesAndIOCs(500, 50);
    onProgress?.(80);

    const allIocCount = await syncAllIOCs(5000);
    onProgress?.(88);

    const cveCount = await syncCVEs(500);
    onProgress?.(92);

    let similarityCount = 0;
    try {
        similarityCount = await syncSimilarIOCs(200, 0.75, 5);
    } catch (err) {
        log.warn('Similarity sync skipped', { error: err });
    }
    onProgress?.(95);

    const driver = getNeo4jDriver();
    const session = driver.session();
    let totalNodes = 0;
    let totalEdges = 0;
    try {
        const nodeResult = await session.run('MATCH (n) RETURN count(n) AS c');
        totalNodes = neo4j.integer.toNumber(nodeResult.records[0]?.get('c') ?? 0);
        const edgeResult = await session.run('MATCH ()-[r]->() RETURN count(r) AS c');
        totalEdges = neo4j.integer.toNumber(edgeResult.records[0]?.get('c') ?? 0);
    } finally {
        await session.close();
    }

    onProgress?.(100);

    const duration = Date.now() - start;
    log.info('Sync complete', { durationMs: duration, totalNodes, totalEdges });

    return {
        actors: actorCount,
        tactics: tacticCount,
        techniques: techCount,
        malware: malwareCount,
        tools: toolCount,
        relationships: relCount,
        pulses: pulseCount,
        iocs: iocCount,
        cves: cveCount,
        totalNodes,
        totalEdges,
        durationMs: duration,
    };
}
