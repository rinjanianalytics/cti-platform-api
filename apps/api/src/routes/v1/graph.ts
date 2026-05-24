/**
 * Graph Routes (Layout + Neo4j Exploration)
 *
 * Extracted from v1.ts — server-side graph layout and Neo4j database endpoints.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import * as opensearch from '../../services/opensearch';
import {
    GraphLayoutSchema, Neo4jSearchSchema, Neo4jExpandSchema,
    Neo4jPathSchema, LimitSchema, Neo4jSyncSchema, CypherQuerySchema,
} from '../../lib/schemas';
import { checkNeo4jHealth, getNeo4jStats } from '../../services/neo4j';
import {
    neighborhoodExpand, findShortestPath, getAttackTree,
    iocPivot, findRelatedActors, executeCypher, graphSearch,
} from '../../services/neo4jGraph';
import { neo4jSyncQueue } from '../../queues/index';

const router = new Hono();

// ============================================================================
// Graph Layout (Server-Side Pre-computation)
// ============================================================================

router.get('/graph/layout', async (c) => {
    const { maxIOCs, maxActors, maxCVEs, width, height } = GraphLayoutSchema.parse(c.req.query());

    // Fetch entities from OpenSearch
    const [iocResult, actorResult, cveResult] = await Promise.all([
        opensearch.unifiedSearch({
            query: '',
            filters: { entityType: ['ioc'] },
            pagination: { page: 1, limit: Math.min(maxIOCs, 100) },
            sort: { field: 'updatedAt', order: 'desc' },
            aggregations: false,
        }),
        opensearch.unifiedSearch({
            query: '',
            filters: { entityType: ['threat-actor'] },
            pagination: { page: 1, limit: Math.min(maxActors, 50) },
            sort: { field: 'updatedAt', order: 'desc' },
            aggregations: false,
        }),
        opensearch.unifiedSearch({
            query: '',
            filters: { entityType: ['vulnerability'] },
            pagination: { page: 1, limit: Math.min(maxCVEs, 50) },
            sort: { field: 'updatedAt', order: 'desc' },
            aggregations: false,
        }),
    ]);

    // Import graph layout service dynamically
    const { computeGraphLayout } = await import('../../services/graphLayout');

    // Compute layout server-side (async — queries PostgreSQL for real relationships)
    const layout = await computeGraphLayout(
        iocResult.items,
        actorResult.items,
        cveResult.items,
        width,
        height,
    );

    // Cache for 5 minutes
    c.header('Cache-Control', 'public, max-age=300');

    return c.json({
        success: true,
        data: layout,
    });
});

// ============================================================================
// Neo4j Graph Database Exploration
// ============================================================================

// Health / Stats
router.get('/graph/neo4j/health', async (c) => {
    const health = await checkNeo4jHealth();
    return c.json({ success: true, data: health });
});

router.get('/graph/neo4j/stats', async (c) => {
    const stats = await getNeo4jStats();
    return c.json({ success: true, data: stats });
});

// Trigger sync (POST → BullMQ job)
router.post('/graph/neo4j/sync', async (c) => {
    const { syncType, options } = Neo4jSyncSchema.parse(await c.req.json().catch(() => ({})));

    const job = await neo4jSyncQueue.add(`neo4j-sync-${syncType}`, {
        syncType,
        options,
    });

    return c.json({
        success: true,
        data: {
            jobId: job.id,
            syncType,
            message: `Neo4j sync job queued: ${syncType}`,
        },
    });
});

// Fuzzy graph search
router.get('/graph/neo4j/search', async (c) => {
    const { q, limit } = Neo4jSearchSchema.parse(c.req.query());
    const result = await graphSearch(q, limit);
    return c.json({ success: true, data: result });
});

// Neighborhood expand
router.get('/graph/neo4j/expand/:nodeId', async (c) => {
    const { nodeId } = c.req.param();
    const { depth, limit } = Neo4jExpandSchema.parse(c.req.query());

    const result = await neighborhoodExpand(nodeId, depth, limit);
    return c.json({ success: true, data: result });
});

// Shortest path
router.get('/graph/neo4j/path', async (c) => {
    const { from, to, maxDepth } = Neo4jPathSchema.parse(c.req.query());
    const result = await findShortestPath(from, to, maxDepth);
    return c.json({ success: true, data: result });
});

// Attack tree
router.get('/graph/neo4j/attack-tree/:actor', async (c) => {
    const { actor } = c.req.param();
    const result = await getAttackTree(decodeURIComponent(actor));
    return c.json({ success: true, data: result });
});

// IOC pivot
router.get('/graph/neo4j/ioc-pivot/:iocValue', async (c) => {
    const { iocValue } = c.req.param();
    const { limit } = LimitSchema.parse(c.req.query());
    const result = await iocPivot(decodeURIComponent(iocValue), limit);
    return c.json({ success: true, data: result });
});

// Related actors
router.get('/graph/neo4j/related-actors/:actor', async (c) => {
    const { actor } = c.req.param();
    const minShared = z.coerce.number().int().min(1).max(100).default(1)
        .parse(c.req.query('minShared'));
    const result = await findRelatedActors(decodeURIComponent(actor), minShared);
    return c.json({ success: true, data: result });
});

// Raw Cypher query (read-only, for advanced analysts)
router.post('/graph/neo4j/cypher', async (c) => {
    const { query, params, limit } = CypherQuerySchema.parse(await c.req.json().catch(() => ({})));

    const result = await executeCypher(query, params || {}, limit || 100);
    return c.json({ success: true, data: result });
});

export default router;
