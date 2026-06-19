/**
 * Neo4j Full Sync Orchestrator
 *
 * Coordinates all sync operations in dependency order.
 */

import { getNeo4jDriver, ensureNeo4jConstraints } from '../driver';
import neo4j from 'neo4j-driver';
import { syncActors, syncTactics, syncTechniques, syncMalware, syncTools, syncTelco, syncWallets, syncFrameworks } from '../syncEntities';
import { syncRelationships, syncGenericRelationships } from '../syncRelationships';
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
    genericRelationships: number;
    telco: number;
    wallets: number;
    frameworks: number;
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

    // Telco nodes must exist BEFORE syncRelationships() so telco edges can
    // MATCH their endpoints and hydrate (B1.2).
    const telcoCounts = await syncTelco();
    const telcoCount = telcoCounts.networkElements + telcoCounts.signalingInterfaces + telcoCounts.fraudSchemes;
    // Wallet nodes before relationships, same ordering rule as telco — fund-flow
    // edges (cashed-out-to, sent-funds-to) can only hydrate once both endpoints exist.
    const walletCount = await syncWallets();
    // FiGHT/ATLAS technique nodes before relationships, so the telco→FiGHT
    // bridge (fraud_scheme -[uses]-> fight_technique) and actor→technique edges hydrate.
    const frameworkCounts = await syncFrameworks();
    const frameworkCount = frameworkCounts.fightTechniques + frameworkCounts.atlasTechniques;
    onProgress?.(68);

    const relCount = await syncRelationships();
    // syncRelationships() only hydrates USES (it resolves STIX UUID→MITRE ID).
    // This second pass re-hydrates every OTHER graph-participating edge —
    // telco (EXPLOITS_VIA, USES_INTERFACE, …) and STIX SDO links — so the graph
    // is a true projection of Postgres, not dependent on insert ordering. This
    // is what the "telco nodes must exist before syncRelationships()" comment
    // above always assumed existed.
    const genericRelCount = await syncGenericRelationships();
    onProgress?.(75);

    // 2000 cap (was 500) so the full sync covers the entire pulse corpus with
    // headroom — paired with newest-first ordering in syncPulsesAndIOCs, this
    // makes the graph a true projection of Postgres rather than the first 500 rows.
    const { pulses: pulseCount, iocs: iocCount, links: linkCount } = await syncPulsesAndIOCs(2000, 50);
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
        genericRelationships: genericRelCount,
        telco: telcoCount,
        wallets: walletCount,
        frameworks: frameworkCount,
        pulses: pulseCount,
        iocs: iocCount,
        cves: cveCount,
        totalNodes,
        totalEdges,
        durationMs: duration,
    };
}
