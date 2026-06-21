/**
 * Neo4j Driver Singleton
 *
 * Connection management, health checks, and schema constraints.
 */

import neo4j, { Driver } from 'neo4j-driver';
import { createLogger } from '../../lib/logger';

const log = createLogger('Neo4j');

// ============================================================================
// Driver Singleton
// ============================================================================

let _driver: Driver | null = null;

const NEO4J_URI = process.env.NEO4J_URI || 'bolt://localhost:7687';
const NEO4J_USER = process.env.NEO4J_USER || 'neo4j';
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'rinjani1';

export function getNeo4jDriver(): Driver {
    if (!_driver) {
        _driver = neo4j.driver(
            NEO4J_URI,
            neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD),
            {
                maxConnectionPoolSize: 50,
                connectionAcquisitionTimeout: 30000,
                logging: {
                    level: 'warn',
                    logger: (level, message) => log.info(`Driver: ${message}`, { level }),
                },
            },
        );
        log.info('Driver created', { uri: NEO4J_URI });
    }
    return _driver;
}

export async function closeNeo4j(): Promise<void> {
    if (_driver) {
        await _driver.close();
        _driver = null;
        log.info('Driver closed');
    }
}

export async function checkNeo4jHealth(): Promise<{ connected: boolean; serverInfo?: string }> {
    try {
        const driver = getNeo4jDriver();
        const info = await driver.getServerInfo();
        return { connected: true, serverInfo: `${info.address} (${info.protocolVersion})` };
    } catch {
        return { connected: false };
    }
}

// ============================================================================
// Schema Constraints (run once)
// ============================================================================

export async function ensureNeo4jConstraints(): Promise<void> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    const constraints = [
        'CREATE CONSTRAINT actor_stix IF NOT EXISTS FOR (a:Actor) REQUIRE a.stixId IS UNIQUE',
        'CREATE CONSTRAINT technique_mitre IF NOT EXISTS FOR (t:Technique) REQUIRE t.mitreId IS UNIQUE',
        'CREATE CONSTRAINT tactic_mitre IF NOT EXISTS FOR (t:Tactic) REQUIRE t.mitreId IS UNIQUE',
        'CREATE CONSTRAINT malware_stix IF NOT EXISTS FOR (m:Malware) REQUIRE m.stixId IS UNIQUE',
        'CREATE CONSTRAINT tool_mitre IF NOT EXISTS FOR (t:Tool) REQUIRE t.mitreId IS UNIQUE',
        'CREATE CONSTRAINT ioc_id IF NOT EXISTS FOR (i:IOC) REQUIRE i.pgId IS UNIQUE',
        'CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cveId IS UNIQUE',
        'CREATE CONSTRAINT pulse_otx IF NOT EXISTS FOR (p:Pulse) REQUIRE p.otxId IS UNIQUE',
        // Web Intelligence (Phase 44c)
        'CREATE CONSTRAINT websource_id IF NOT EXISTS FOR (w:WebSource) REQUIRE w.itemId IS UNIQUE',
        'CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.pgId IS UNIQUE',
        // Wallet identity (on-chain) — MERGE keys on refId.
        'CREATE CONSTRAINT wallet_ref IF NOT EXISTS FOR (w:Wallet) REQUIRE w.refId IS UNIQUE',
        // Lookup indexes for cross-domain densification (IOC↔Wallet by address):
        // the REFERS_TO pass matches IOC.value per wallet, so IOC.value must be indexed.
        'CREATE INDEX ioc_value IF NOT EXISTS FOR (i:IOC) ON (i.value)',
        'CREATE INDEX wallet_address IF NOT EXISTS FOR (w:Wallet) ON (w.address)',
    ];

    try {
        for (const c of constraints) {
            await session.run(c);
        }
        log.info('Constraints ensured', { count: constraints.length });
    } finally {
        await session.close();
    }
}

// ============================================================================
// Graph Stats
// ============================================================================

export async function getNeo4jStats(): Promise<{ totalNodes: number; totalEdges: number; nodeCounts: Array<{ label: string; count: number }> }> {
    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        const result = await session.run(`
            CALL {
                MATCH (n) RETURN count(n) AS totalNodes
            }
            CALL {
                MATCH ()-[r]->() RETURN count(r) AS totalEdges
            }
            CALL {
                MATCH (n) WITH labels(n) AS lbls, count(*) AS cnt
                UNWIND lbls AS lbl
                RETURN lbl, sum(cnt) AS count ORDER BY count DESC
            }
            RETURN totalNodes, totalEdges, collect({label: lbl, count: count}) AS nodeCounts
        `);

        const record = result.records[0];
        if (!record) return { totalNodes: 0, totalEdges: 0, nodeCounts: [] };

        return {
            totalNodes: neo4j.integer.toNumber(record.get('totalNodes') ?? 0),
            totalEdges: neo4j.integer.toNumber(record.get('totalEdges') ?? 0),
            nodeCounts: record.get('nodeCounts'),
        };
    } finally {
        await session.close();
    }
}
