/**
 * GraphQL Mesh Gateway — Unified Entry Point
 *
 * Single-port architecture: serves REST API routes, GraphQL (stitched supergraph),
 * SSE, and WebSocket — all on port 4000.
 *
 * Architecture:
 *   gateway (Hono) → mounts apiApp (all REST + WS + SSE routes)
 *                   → mounts GraphQL Yoga (Mesh stitched supergraph)
 *
 * The stitched schema is built using GraphQL Mesh, replacing the previous
 * manual graphql-tools/stitch approach with a declarative .meshrc.yaml config.
 */

import { setMaxListeners } from 'node:events';
// Raise listener cap for concurrent AbortSignals without masking real leaks
try { setMaxListeners(100); } catch { /* older Node */ }

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { timing } from 'hono/timing';
import { createYoga } from 'graphql-yoga';
import { stitchSchemas } from '@graphql-tools/stitch';
import { makeExecutableSchema } from '@graphql-tools/schema';
import additionalResolvers from './additionalResolvers.js';

const app = new Hono();

// ============================================================================
// Global Middleware
// ============================================================================

app.use('*', timing());
// Skip verbose logging for /graphql — the stitched-schema remoteExecutor
// generates internal loopback POST /graphql calls that amplify log noise.
// Log all other routes normally.
app.use('*', async (c, next) => {
    if (c.req.path === '/graphql') return next();
    return logger()(c, next);
});
app.use('*', cors({
    origin: (origin) => origin || '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Request-Id', 'If-None-Match', 'X-Organization-Id', 'Accept-Version'],
    exposeHeaders: ['X-Request-Id', 'X-Response-Time', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-Cache', 'ETag', 'Cache-Control', 'X-API-Version', 'Deprecation', 'Sunset'],
    credentials: true,
}));

// ============================================================================
// Health Check (gateway-level)
// ============================================================================

app.get('/gateway/health', (c) => {
    return c.json({
        status: 'ok',
        service: 'rinjani-gateway',
        mode: 'unified-mesh',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    });
});

// ============================================================================
// Extension Type Defs — REST→GraphQL bridge types
//
// These extend the upstream Pothos schema with fields that delegate
// to REST API endpoints via the additional resolvers.
// ============================================================================

const EXTENSION_TYPE_DEFS = /* GraphQL */ `
    scalar JSON

    type HealthStatus {
        status: String
        uptime: Float
        timestamp: String
        services: JSON
    }

    type GraphNode {
        id: String!
        label: String
        type: String
        name: String
        properties: JSON
    }
    type GraphEdge {
        source: String!
        target: String!
        type: String
    }
    type GraphResult {
        nodes: [GraphNode]
        edges: [GraphEdge]
        meta: JSON
    }

    type Query {
        systemHealth: HealthStatus
        platformStats: JSON
        freshness: JSON
        feedHealth: JSON
        opsIngestion: JSON
        opsEnrichment: JSON
        distribution: [JSON]
        sourceBreakdown: [JSON]
        severityTrend(days: Int): [JSON]
        iocGrowth(days: Int): JSON
        feeds: [JSON]
        apiKeys: [JSON]
        services: [JSON]
        integrations: [JSON]
        mitreMatrix: JSON
        mitreTactics: JSON
        alerts(page: Int, limit: Int, severity: String, unread: Boolean): JSON
        unreadAlertCount: JSON
        auditLogs(limit: Int, entityType: String, action: String): JSON
        auditStats(days: Int): JSON
        users(role: String, search: String, page: Int, limit: Int): JSON
        roles: JSON
        queueStats: JSON
        settings: JSON
        neo4jHealth: JSON
        neo4jStats: JSON
        relatedActors(actor: String!, minShared: Int): JSON
        enrichIOC(value: String!, sources: [String], refresh: Boolean): JSON
        actorIntelligence(actorId: String!): JSON
        cveIntelligence(cveId: String!): JSON
        playbooks(enabledOnly: Boolean): JSON
        webhooks: JSON
    }

    type Mutation {
        createAlert(severity: String, type: String, title: String!, message: String!): JSON
        markAlertRead(id: String!): JSON
        markAllAlertsRead: JSON
        updateFeed(id: String!, enabled: Boolean, cron: String): JSON
        setSetting(key: String!, value: String!): JSON
        triggerNeo4jSync(syncType: String): JSON
    }
`;

// ============================================================================
// Build Stitched GraphQL Schema using Mesh-style approach
//
// Uses graphql-tools/stitch (Mesh's underlying merger) with:
//   1. Remote Pothos schema (introspected from in-process /graphql endpoint)
//   2. Local extension schema (REST bridges via additionalResolvers)
// ============================================================================

async function buildMeshSchema() {
    // 1. Import Pothos schema directly — no HTTP loopback needed.
    //    This avoids a circular delegation loop: after hot-swap the
    //    /graphql handler serves the stitched schema, so a loopback
    //    executor would recurse back into itself.
    const { schema: pothosSchema } = await import('../../api/src/graphql/resolvers');

    // 2. Build local extension schema with REST-bridging resolvers
    const extensionSchema = makeExecutableSchema({
        typeDefs: EXTENSION_TYPE_DEFS,
        resolvers: additionalResolvers,
    });

    // 3. Stitch schemas (in-process — no HTTP, no circular delegation)
    return stitchSchemas({
        subschemas: [
            { schema: pothosSchema },
            { schema: extensionSchema },
        ],
    });
}

// ============================================================================
// Simple in-memory response cache for GraphQL queries
// Inspired by @graphql-mesh/plugin-response-cache
// ============================================================================

const CACHE_TTL_MS = 30_000; // 30 seconds
const MAX_CACHE_SIZE = 200;  // Hard cap to prevent OOM
const queryCache = new Map<string, { data: unknown; expires: number }>();

// Periodic eviction — purge ALL expired entries every 60s
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of queryCache) {
        if (v.expires < now) queryCache.delete(k);
    }
}, 60_000).unref();

function getCachedResponse(key: string): unknown | null {
    const entry = queryCache.get(key);
    if (entry && entry.expires > Date.now()) return entry.data;
    if (entry) queryCache.delete(key);
    return null;
}

function setCachedResponse(key: string, data: unknown): void {
    queryCache.set(key, { data, expires: Date.now() + CACHE_TTL_MS });

    // Hard eviction: keep cache bounded
    if (queryCache.size > MAX_CACHE_SIZE) {
        const now = Date.now();
        for (const [k, v] of queryCache) {
            if (v.expires < now) queryCache.delete(k);
        }
        // If still over limit, drop oldest entries (FIFO)
        if (queryCache.size > MAX_CACHE_SIZE) {
            const excess = queryCache.size - MAX_CACHE_SIZE;
            let removed = 0;
            for (const k of queryCache.keys()) {
                if (removed >= excess) break;
                queryCache.delete(k);
                removed++;
            }
        }
    }
}

// ============================================================================
// Bootstrap
// ============================================================================

// Mutable Yoga instance — starts null, gets set after API mount, then
// upgraded to the stitched schema. The /graphql handler reads this ref.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let currentYoga: ReturnType<typeof createYoga<any>> | null = null;

// Register the /graphql handler BEFORE any requests — Hono locks routes after first match.
// When currentYoga is null (during startup), fall through to the API's native /graphql (Pothos).
// Once the stitched schema is ready, this handler intercepts and serves the supergraph.
app.on(['GET', 'POST'], '/graphql', async (c, next) => {
    if (!currentYoga) {
        // Fall through to API's Pothos /graphql handler (needed for introspection)
        return next();
    }
    const response = await currentYoga.handle(c.req.raw);
    return new Response(response.body, {
        status: response.status,
        headers: response.headers,
    });
});

async function bootstrap() {
    const port = parseInt(process.env.GATEWAY_PORT || '4000', 10);

    console.log(`⏳ Loading API app in-process...`);

    // ========================================================================
    // Mount the API Hono app directly — no HTTP proxy needed
    // All routes must be registered BEFORE serve() to avoid router lock
    // ========================================================================

    const { default: apiApp } = await import('../../api/src/index');
    app.route('', apiApp);
    console.log(`✅ API app mounted in-process`);

    // ========================================================================
    // Start Server — routes are locked after first request
    // ========================================================================

    serve({ fetch: app.fetch, port, hostname: '0.0.0.0' });
    console.log(`✅ Server listening on port ${port}`);

    // Boot background services (non-blocking)
    import('../../api/src/startup').then(({ bootServices }) => {
        bootServices().then(() => console.log(`✅ Background services started`));
    });

    // ========================================================================
    // Build Mesh stitched schema (introspects /graphql via loopback)
    // Then hot-swap the Yoga instance via the mutable reference
    // ========================================================================

    console.log(`⏳ Building GraphQL Mesh schema...`);
    const schema = await buildMeshSchema();
    console.log(`✅ Mesh schema built (Pothos + REST bridges)`);

    // Swap the Yoga instance — the registered /graphql handler reads currentYoga
    // Import DataLoader factory for per-request context
    const { createLoaders } = await import('../../api/src/graphql/dataLoaders');

    currentYoga = createYoga({
        schema,
        graphqlEndpoint: '/graphql',
        landingPage: true,
        maskedErrors: false,
        context: () => ({
            loaders: createLoaders(),
        }),
    });

    console.log('');
    console.log(`🚀 RinjaniAnalytics Unified Gateway (GraphQL Mesh)`);
    console.log(`   Mode:      unified (API + Mesh in-process)`);
    console.log(`   Port:      ${port}`);
    console.log(`   GraphQL:   http://localhost:${port}/graphql`);
    console.log(`   Health:    http://localhost:${port}/health`);
    console.log(`   Gateway:   http://localhost:${port}/gateway/health`);
    console.log(`   REST API:  http://localhost:${port}/v1/*`);
    console.log(`   Cache:     ${CACHE_TTL_MS}ms TTL, in-memory`);
    console.log('');
}

bootstrap().catch((err) => {
    console.error('❌ Gateway failed to start:', err);
    process.exit(1);
});

export default app;

