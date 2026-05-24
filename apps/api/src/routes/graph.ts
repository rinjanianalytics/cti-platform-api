/**
 * Graph Explorer Routes
 *
 * Neo4j-powered graph analysis endpoints:
 *   - Neighborhood expansion (N-hop traversal)
 *   - Shortest path between entities
 *   - ATT&CK tree (Actor → Techniques → Tactics)
 *   - IOC pivot (IOC → Pulse → Actor → related IOCs)
 *   - Related actors (shared techniques)
 *   - Campaign detection (cluster sources by shared IOCs)
 *   - Source influence (rank web sources)
 *   - Actor attribution (IOC → WebSource → Actor)
 *   - Raw Cypher (admin only)
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
    neighborhoodExpand,
    findShortestPath,
    getAttackTree,
    iocPivot,
    findRelatedActors,
    executeCypher,
} from '../services/neo4jGraph';
import { requireAuth, requireRole } from '../middleware/auth';
import { ValidationError, ForbiddenError } from '../lib/errors';
import {
    Neo4jExpandSchema, Neo4jPathSchema, LimitSchema,
} from '../lib/schemas';

const graph = new Hono();

// =============================================================================
// GET /graph/expand/:id — Neighborhood expansion
// =============================================================================
graph.get('/expand/:id', async (c) => {
    const id = c.req.param('id');
    const { depth, limit } = Neo4jExpandSchema.parse(c.req.query());

    const result = await neighborhoodExpand(id, depth, limit);
    return c.json({
        success: true,
        data: result,
        meta: { requestId: crypto.randomUUID() },
    });
});

// =============================================================================
// GET /graph/path — Shortest path between two entities
// =============================================================================
graph.get('/path', async (c) => {
    const { from, to, maxDepth } = Neo4jPathSchema.parse(c.req.query());

    const result = await findShortestPath(from, to, maxDepth);
    return c.json({
        success: true,
        data: result,
        meta: { requestId: crypto.randomUUID() },
    });
});

// =============================================================================
// GET /graph/attack-tree/:actor — ATT&CK tree for an actor
// =============================================================================
graph.get('/attack-tree/:actor', async (c) => {
    const actor = decodeURIComponent(c.req.param('actor'));

    const result = await getAttackTree(actor);
    return c.json({
        success: true,
        data: result,
        meta: { requestId: crypto.randomUUID() },
    });
});

// =============================================================================
// GET /graph/ioc-pivot/:value — IOC pivot traversal
// =============================================================================
graph.get('/ioc-pivot/:value', async (c) => {
    const value = decodeURIComponent(c.req.param('value'));
    const { limit: maxResults } = LimitSchema.parse(c.req.query());

    const result = await iocPivot(value, maxResults);
    return c.json({
        success: true,
        data: result,
        meta: { requestId: crypto.randomUUID() },
    });
});

// =============================================================================
// GET /graph/related-actors/:actor — Actors sharing techniques
// =============================================================================
graph.get('/related-actors/:actor', async (c) => {
    const actor = decodeURIComponent(c.req.param('actor'));
    const minShared = z.coerce.number().int().min(1).max(100).default(1)
        .parse(c.req.query('minShared'));

    const result = await findRelatedActors(actor, minShared);
    return c.json({
        success: true,
        data: result,
        meta: { requestId: crypto.randomUUID() },
    });
});

// =============================================================================
// POST /graph/cypher — Raw read-only Cypher (admin only)
// =============================================================================
graph.post('/cypher', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json();
    const { query, params = {}, limit = 100 } = body;

    if (!query) {
        throw new ValidationError('query is required');
    }

    // Block write operations
    const normalized = query.toUpperCase().trim();
    if (/\b(CREATE|MERGE|DELETE|SET|REMOVE|DROP|DETACH)\b/.test(normalized)) {
        throw new ForbiddenError('Write operations are not allowed. Only read queries (MATCH, RETURN, etc.) are permitted.');
    }

    const result = await executeCypher(query, params, Math.min(limit, 500));
    return c.json({
        success: true,
        data: result,
        meta: { requestId: crypto.randomUUID(), resultCount: result.length },
    });
});

export default graph;
