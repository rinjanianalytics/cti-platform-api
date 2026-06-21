/**
 * Neo4j Graph Traversal — Search, Expand, Shortest Path, Attack Tree, IOC Pivot
 */

import { getNeo4jDriver } from '../neo4j';
import neo4j from 'neo4j-driver';
import type { Node as Neo4jNode, Relationship as Neo4jRelationship } from 'neo4j-driver';
import { log, toGraphNode, toGraphEdge, nodeId, dedup } from './graphTypes';
import type { GraphNode, GraphEdge, GraphResult } from './graphTypes';

// ============================================================================
// Fuzzy Graph Search (CONTAINS matching)
// ============================================================================

/**
 * Search for nodes by partial name/value/ID match.
 * Returns matching nodes + their direct relationships.
 */
export async function graphSearch(
    query: string,
    limit: number = 50,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();
    const lowerQ = query.toLowerCase();

    try {
        log.info('Fuzzy search', { query, limit });

        const result = await session.run(`
            MATCH (n)
            WHERE toLower(n.name) CONTAINS $q
               OR toLower(n.value) CONTAINS $q
               OR toLower(n.stixId) CONTAINS $q
               OR toLower(n.mitreId) CONTAINS $q
               OR toLower(n.cveId) CONTAINS $q
            WITH n LIMIT $limit
            OPTIONAL MATCH (n)-[r]-(m)
            WHERE m IN collect { MATCH (n2) WHERE toLower(n2.name) CONTAINS $q OR toLower(n2.value) CONTAINS $q OR toLower(n2.stixId) CONTAINS $q OR toLower(n2.mitreId) CONTAINS $q OR toLower(n2.cveId) CONTAINS $q RETURN n2 LIMIT $limit }
               OR true
            WITH n, collect(DISTINCT r)[0..5] AS rels, collect(DISTINCT m)[0..5] AS connected
            RETURN collect(DISTINCT n) AS matchedNodes,
                   reduce(acc = [], r IN collect(rels) | acc + r) AS allRels,
                   reduce(acc = [], c IN collect(connected) | acc + c) AS connectedNodes
        `, { q: lowerQ, limit: neo4j.int(limit) });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        if (result.records.length > 0) {
            const record = result.records[0];
            const matchedNodes: Neo4jNode[] = record.get('matchedNodes') || [];

            const nodeById = new Map<string, Neo4jNode>();
            for (const n of matchedNodes) {
                if (n) {
                    nodeById.set(n.elementId, n);
                    nodes.push(toGraphNode(n));
                }
            }

            // Also add connected nodes
            const connectedNodes: Neo4jNode[] = record.get('connectedNodes') || [];
            for (const list of connectedNodes) {
                if (Array.isArray(list)) {
                    for (const n of list) {
                        if (n && !nodeById.has(n.elementId)) {
                            nodeById.set(n.elementId, n);
                            nodes.push(toGraphNode(n));
                        }
                    }
                } else if (list && !nodeById.has(list.elementId)) {
                    nodeById.set(list.elementId, list);
                    nodes.push(toGraphNode(list));
                }
            }

            // Process relationships
            const allRels: Neo4jRelationship[] = record.get('allRels') || [];
            for (const rList of allRels) {
                const items = Array.isArray(rList) ? rList : [rList];
                for (const r of items) {
                    if (r) {
                        const src = nodeById.get(r.startNodeElementId);
                        const tgt = nodeById.get(r.endNodeElementId);
                        if (src && tgt) edges.push(toGraphEdge(r, src, tgt));
                    }
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        log.info('Search results', { nodes: dn.length, edges: de.length, query });
        return { nodes: dn, edges: de, meta: { query, matchCount: dn.length } };
    } catch (err) {
        // Fallback: simpler query without relationships if the complex one fails
        log.warn('Complex query failed, trying simple', { error: err });
        try {
            const simpleResult = await session.run(`
                MATCH (n)
                WHERE toLower(n.name) CONTAINS $q
                   OR toLower(n.value) CONTAINS $q
                   OR toLower(n.stixId) CONTAINS $q
                   OR toLower(n.mitreId) CONTAINS $q
                   OR toLower(n.cveId) CONTAINS $q
                RETURN n LIMIT $limit
            `, { q: lowerQ, limit: neo4j.int(limit) });

            const nodes: GraphNode[] = [];
            for (const rec of simpleResult.records) {
                const n = rec.get('n');
                if (n) nodes.push(toGraphNode(n));
            }
            return { nodes, edges: [], meta: { query, matchCount: nodes.length, simple: true } };
        } catch (err2) {
            log.error('Simple query also failed', err2 instanceof Error ? err2 : new Error(String(err2)));
            return { nodes: [], edges: [], meta: { query, matchCount: 0, error: String(err2) } };
        }
    } finally {
        await session.close();
    }
}

// ============================================================================
// Neighborhood Expand
// ============================================================================

/**
 * Expand N hops from any node.
 */
export async function neighborhoodExpand(
    nodeIdentifier: string,
    depth: number = 1,
    limit: number = 100,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();
    const clampedDepth = Math.min(Math.max(depth, 1), 4);

    try {
        log.info('Neighborhood expand', { nodeIdentifier, depth, limit });

        const result = await session.run(`
            MATCH (start)
            WHERE start.stixId = $id
               OR start.mitreId = $id
               OR start.cveId = $id
               OR start.otxId = $id
               OR start.pgId = $id
               OR start.value = $id
               OR toLower(start.name) = toLower($id)
            WITH start LIMIT 1
            CALL {
                WITH start
                MATCH path = (start)-[*1..${clampedDepth}]-(connected)
                RETURN path
                LIMIT $limit
            }
            WITH start, path
            UNWIND nodes(path) AS n
            UNWIND relationships(path) AS r
            WITH collect(DISTINCT n) AS allNodes, collect(DISTINCT r) AS allRels
            RETURN allNodes, allRels
        `, { id: nodeIdentifier, limit: neo4j.int(limit) });

        log.info('Expand query records', { count: result.records.length });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        if (result.records.length > 0) {
            const record = result.records[0];
            const allNodes: Neo4jNode[] = record.get('allNodes') || [];
            const allRels: Neo4jRelationship[] = record.get('allRels') || [];

            // Build node map for edge resolution
            const nodeById = new Map<string, Neo4jNode>();
            for (const n of allNodes) {
                nodeById.set(n.elementId, n);
                nodes.push(toGraphNode(n));
            }

            for (const r of allRels) {
                const src = nodeById.get(r.startNodeElementId);
                const tgt = nodeById.get(r.endNodeElementId);
                if (src && tgt) {
                    edges.push(toGraphEdge(r, src, tgt));
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return { nodes: dn, edges: de, meta: { depth: clampedDepth, limit } };
    } finally {
        await session.close();
    }
}


// ============================================================================
// Shortest Path
// ============================================================================

/**
 * Find shortest path between two entities.
 */
export async function findShortestPath(
    fromId: string,
    toId: string,
    maxDepth: number = 6,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (start)
            WHERE start.stixId = $from
               OR start.mitreId = $from
               OR start.cveId = $from
               OR start.otxId = $from
               OR start.pgId = $from
               OR start.value = $from
               OR toLower(start.name) = toLower($from)
            WITH start LIMIT 1
            MATCH (end)
            WHERE end.stixId = $to
               OR end.mitreId = $to
               OR end.cveId = $to
               OR end.otxId = $to
               OR end.pgId = $to
               OR end.value = $to
               OR toLower(end.name) = toLower($to)
            WITH start, end LIMIT 1
            MATCH path = shortestPath((start)-[*..${Math.min(maxDepth, 10)}]-(end))
            RETURN nodes(path) AS pathNodes, relationships(path) AS pathRels
        `, { from: fromId, to: toId });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        if (result.records.length > 0) {
            const record = result.records[0];
            const pathNodes: Neo4jNode[] = record.get('pathNodes') || [];
            const pathRels: Neo4jRelationship[] = record.get('pathRels') || [];

            const nodeById = new Map<string, Neo4jNode>();
            for (const n of pathNodes) {
                nodeById.set(n.elementId, n);
                nodes.push(toGraphNode(n));
            }
            for (const r of pathRels) {
                const src = nodeById.get(r.startNodeElementId);
                const tgt = nodeById.get(r.endNodeElementId);
                if (src && tgt) edges.push(toGraphEdge(r, src, tgt));
            }
        }

        return { nodes, edges, meta: { from: fromId, to: toId, pathLength: edges.length } };
    } finally {
        await session.close();
    }
}

// ============================================================================
// Attack Tree
// ============================================================================

/**
 * Full ATT&CK tree for an actor: Actor → Techniques → Tactics
 */
export async function getAttackTree(actorName: string): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (a:Actor)
            WHERE toLower(a.name) = toLower($name)
               OR toLower(a.stixId) = toLower($name)
            WITH a LIMIT 1
            OPTIONAL MATCH (a)-[r1:USES]->(t:Technique)
            OPTIONAL MATCH (t)-[r2:BELONGS_TO]->(tac:Tactic)
            OPTIONAL MATCH (a)-[r3:USES]->(m:Malware)
            OPTIONAL MATCH (a)-[r4:USES]->(tool:Tool)
            WITH a, 
                 collect(DISTINCT t) AS techniques,
                 collect(DISTINCT tac) AS tactics,
                 collect(DISTINCT m) AS malwares,
                 collect(DISTINCT tool) AS tools,
                 collect(DISTINCT r1) AS techRels,
                 collect(DISTINCT r2) AS tacRels,
                 collect(DISTINCT r3) AS malRels,
                 collect(DISTINCT r4) AS toolRels
            RETURN a, techniques, tactics, malwares, tools, techRels, tacRels, malRels, toolRels
        `, { name: actorName });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        if (result.records.length > 0) {
            const rec = result.records[0];
            const actor = rec.get('a');

            if (actor) {
                nodes.push(toGraphNode(actor));

                const nodeById = new Map<string, Neo4jNode>();
                nodeById.set(actor.elementId, actor);

                // Process all entity lists
                for (const listName of ['techniques', 'tactics', 'malwares', 'tools'] as const) {
                    const list: Neo4jNode[] = rec.get(listName) || [];
                    for (const n of list) {
                        if (n) {
                            nodeById.set(n.elementId, n);
                            nodes.push(toGraphNode(n));
                        }
                    }
                }

                // Process all relationship lists
                for (const relName of ['techRels', 'tacRels', 'malRels', 'toolRels'] as const) {
                    const rels: Neo4jRelationship[] = rec.get(relName) || [];
                    for (const r of rels) {
                        if (r) {
                            const src = nodeById.get(r.startNodeElementId);
                            const tgt = nodeById.get(r.endNodeElementId);
                            if (src && tgt) edges.push(toGraphEdge(r, src, tgt));
                        }
                    }
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return { nodes: dn, edges: de, meta: { actor: actorName } };
    } finally {
        await session.close();
    }
}

// ============================================================================
// IOC Pivot
// ============================================================================

/**
 * Pivot from an IOC: IOC → Pulse → Actor → other IOCs
 */
export async function iocPivot(
    iocValue: string,
    maxResults: number = 50,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (ioc:IOC)
            WHERE ioc.value = $value OR ioc.pgId = $value
            WITH ioc LIMIT 1
            OPTIONAL MATCH (ioc)-[r1:FOUND_IN]->(pulse:Pulse)
            OPTIONAL MATCH (pulse)-[r2:ATTRIBUTED_TO]->(actor:Actor)
            OPTIONAL MATCH (otherIOC:IOC)-[r3:FOUND_IN]->(pulse)
            WHERE otherIOC <> ioc
            // Cross-domain reach (densifyCrossDomain): the on-chain Wallet the IOC
            // refers to (same address) and the actor attributed directly to the IOC.
            OPTIONAL MATCH (ioc)-[r4:REFERS_TO]->(wallet:Wallet)
            OPTIONAL MATCH (ioc)-[r5:ATTRIBUTED_TO]->(directActor:Actor)
            WITH ioc, pulse, actor, r1, r2,
                 collect(DISTINCT otherIOC)[0..$limit] AS relatedIOCs,
                 collect(DISTINCT r3)[0..$limit] AS relatedRels,
                 collect(DISTINCT wallet) AS wallets,
                 collect(DISTINCT r4) AS walletRels,
                 collect(DISTINCT directActor) AS directActors,
                 collect(DISTINCT r5) AS directActorRels
            RETURN ioc, pulse, actor, r1, r2, relatedIOCs, relatedRels,
                   wallets, walletRels, directActors, directActorRels
        `, { value: iocValue, limit: neo4j.int(maxResults) });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        for (const rec of result.records) {
            const nodeById = new Map<string, Neo4jNode>();

            for (const key of ['ioc', 'pulse', 'actor']) {
                const n = rec.get(key);
                if (n) {
                    nodeById.set(n.elementId, n);
                    nodes.push(toGraphNode(n));
                }
            }

            for (const key of ['r1', 'r2']) {
                const r = rec.get(key);
                if (r) {
                    const src = nodeById.get(r.startNodeElementId);
                    const tgt = nodeById.get(r.endNodeElementId);
                    if (src && tgt) edges.push(toGraphEdge(r, src, tgt));
                }
            }

            const relatedIOCs: Neo4jNode[] = rec.get('relatedIOCs') || [];
            for (const n of relatedIOCs) {
                if (n) {
                    nodeById.set(n.elementId, n);
                    nodes.push(toGraphNode(n));
                }
            }

            const relatedRels: Neo4jRelationship[] = rec.get('relatedRels') || [];
            for (const r of relatedRels) {
                if (r) {
                    const src = nodeById.get(r.startNodeElementId);
                    const tgt = nodeById.get(r.endNodeElementId);
                    if (src && tgt) edges.push(toGraphEdge(r, src, tgt));
                }
            }

            // Cross-domain nodes: on-chain wallets (REFERS_TO) + directly-attributed actors.
            for (const key of ['wallets', 'directActors']) {
                const arr: Neo4jNode[] = rec.get(key) || [];
                for (const n of arr) {
                    if (n) {
                        nodeById.set(n.elementId, n);
                        nodes.push(toGraphNode(n));
                    }
                }
            }
            for (const key of ['walletRels', 'directActorRels']) {
                const arr: Neo4jRelationship[] = rec.get(key) || [];
                for (const r of arr) {
                    if (r) {
                        const src = nodeById.get(r.startNodeElementId);
                        const tgt = nodeById.get(r.endNodeElementId);
                        if (src && tgt) edges.push(toGraphEdge(r, src, tgt));
                    }
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return { nodes: dn, edges: de, meta: { ioc: iocValue } };
    } finally {
        await session.close();
    }
}
