/**
 * Neo4j Graph Analysis — Related Actors, Raw Cypher
 */

import { getNeo4jDriver } from '../neo4j';
import neo4j from 'neo4j-driver';
import type { Node as Neo4jNode } from 'neo4j-driver';
import { log, toGraphNode, nodeId, dedup } from './graphTypes';
import type { GraphNode, GraphEdge, GraphResult } from './graphTypes';

// ============================================================================
// Related Actors (shared techniques)
// ============================================================================

/**
 * Find actors that share techniques with a given actor.
 */
export async function findRelatedActors(
    actorName: string,
    minShared: number = 1,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (a:Actor)
            WHERE toLower(a.name) = toLower($name)
               OR a.stixId = $name
            WITH a LIMIT 1
            MATCH (a)-[:USES]->(t:Technique)<-[:USES]-(related:Actor)
            WHERE related <> a
            WITH a, related, collect(DISTINCT t) AS sharedTechs
            WHERE size(sharedTechs) >= $minShared
            RETURN a, related, sharedTechs
            ORDER BY size(sharedTechs) DESC
            LIMIT 20
        `, { name: actorName, minShared: neo4j.int(minShared) });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        for (const rec of result.records) {
            const actor = rec.get('a');
            const related = rec.get('related');
            const sharedTechs: Neo4jNode[] = rec.get('sharedTechs') || [];

            if (actor) nodes.push(toGraphNode(actor));
            if (related) nodes.push(toGraphNode(related));

            for (const t of sharedTechs) {
                if (t) {
                    nodes.push(toGraphNode(t));
                    // Add edges: actor→tech, related→tech
                    if (actor) edges.push({
                        source: nodeId(actor),
                        target: nodeId(t),
                        type: 'USES',
                        properties: {},
                    });
                    if (related) edges.push({
                        source: nodeId(related),
                        target: nodeId(t),
                        type: 'USES',
                        properties: {},
                    });
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return {
            nodes: dn,
            edges: de,
            meta: {
                actor: actorName,
                relatedActorCount: result.records.length,
            },
        };
    } finally {
        await session.close();
    }
}
// ============================================================================
// Raw Cypher (for advanced analysts)
// ============================================================================

/**
 * Execute a read-only Cypher query (for admin/analyst use).
 * Note: Only read operations are allowed.
 */
export async function executeCypher(
    query: string,
    params: Record<string, unknown> = {},
    limit: number = 100,
): Promise<Record<string, unknown>[]> {
    // Safety: block write operations
    const upper = query.toUpperCase().trim();
    if (upper.includes('DELETE') || upper.includes('DETACH') ||
        upper.includes('CREATE') || upper.includes('MERGE') ||
        upper.includes('SET ') || upper.includes('REMOVE')) {
        throw new Error('Write operations are not allowed via the Cypher query endpoint');
    }

    const driver = getNeo4jDriver();
    const session = driver.session({ defaultAccessMode: neo4j.session.READ });
    try {
        const result = await session.run(query, params);
        return result.records.slice(0, limit).map(rec => {
            const obj: Record<string, unknown> = {};
            for (const key of rec.keys as string[]) {
                const val = rec.get(key as string);
                if (val?.properties) {
                    obj[key as string] = { labels: val.labels, ...val.properties };
                } else if (val?.toNumber) {
                    obj[key as string] = val.toNumber();
                } else {
                    obj[key as string] = val;
                }
            }
            return obj;
        });
    } finally {
        await session.close();
    }
}
