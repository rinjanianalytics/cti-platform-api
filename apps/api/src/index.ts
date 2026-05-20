/**
 * V3 Backend API - Entry Point
 *
 * Main entry point for the Hono-based API server.
 * All handler logic is in route modules; this file is purely composition.
 */

// OpenTelemetry must be imported FIRST to instrument all subsequent modules
import './telemetry/otel';

// Environment validation runs at import time — crash fast on missing/invalid config
import './lib/env';

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { timing } from 'hono/timing';
import { compress } from 'hono/compress';
import crypto from 'crypto';
import { createLogger } from './lib/logger';

const log = createLogger('Server');

// Route imports
import healthRoutes from './routes/health';
import v1Router from './routes/v1';
import v2Router from './routes/v2';
import opengateRouter from './routes/opengate';
import notificationsRouter from './routes/notifications';
import usersRouter from './routes/users';
import adminRouter from './routes/admin';
import alertsRouter from './routes/alerts';
import opsRouter from './routes/ops';
import nexusRoutes from './routes/nexus';
import webSearchRoutes from './routes/webSearch';
import streamRoutes from './routes/streaming';
import taxiiRouter from './routes/taxii';
import sseRouter from './routes/sse';
import { optionalAuth, authRouter, validateAuthConfig } from './middleware/auth';
import { keycloakAuth } from './services/keycloak';
import { errorHandler } from './middleware/error';
import { rateLimiter } from './middleware/rateLimit';
import { cacheMiddleware, cacheRouter } from './middleware/cache';
import { apiVersioning } from './middleware/versioning';

// ============================================================================
// Create App
// ============================================================================

const app = new Hono();

// Global middleware
app.use('*', timing());
app.use('*', logger());
app.use('*', secureHeaders());
app.use('*', compress());

// Response time tracking (sub-ms precision)
app.use('*', async (c, next) => {
    const start = performance.now();
    await next();
    c.header('X-Response-Time', `${(performance.now() - start).toFixed(2)}ms`);
});

// Request ID propagation
app.use('*', async (c, next) => {
    const requestId = c.req.header('X-Request-Id') || crypto.randomUUID();
    c.header('X-Request-Id', requestId);
    await next();
});

// CORS — production uses CORS_ORIGINS env var (comma-separated domain list, or '*' for all)
const rawCorsOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000').trim();
const corsOriginOption = rawCorsOrigins === '*'
    ? (origin: string) => origin   // Allow all origins (reflect request origin)
    : rawCorsOrigins.split(',').map(o => o.trim());

app.use('*', cors({
    origin: corsOriginOption,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Request-Id', 'If-None-Match', 'X-Organization-Id', 'Accept-Version'],
    exposeHeaders: ['X-Request-Id', 'X-Response-Time', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'X-Cache', 'ETag', 'Cache-Control', 'X-API-Version', 'Deprecation', 'Sunset'],
    credentials: true,
}));

// API versioning headers
app.use('/v1/*', apiVersioning());
app.use('/v2/*', apiVersioning());

// Optional auth (needed for rate limiting to know user role)
app.use('*', optionalAuth);

// Rate limiting (after auth so we can use role-based limits)
app.use('/v1/*', rateLimiter());
app.use('/v2/*', rateLimiter());
app.use('/graphql', rateLimiter());
app.use('/taxii2/*', rateLimiter());

// Keycloak OIDC auth for admin endpoints (optional — falls through when Keycloak is unavailable)
app.use('/admin/*', keycloakAuth({ optional: true }));

// Caching for stats, monitoring, and ops endpoints
app.use('/v1/stats*', cacheMiddleware(60));
app.use('/v1/monitoring/*', cacheMiddleware(30));
app.use('/v1/ops/*', cacheMiddleware(30));
app.use('/v1/graph/layout', cacheMiddleware(300));
app.use('/health', cacheMiddleware(10));

// Error handler
app.onError(errorHandler);

// ============================================================================
// Routes
// ============================================================================

// Health, info, and API docs
app.route('/', healthRoutes);

// Versioned API routes
app.route('/v1', v1Router);
app.route('/v2', v2Router);
app.route('/auth', authRouter);
app.route('/opengate', opengateRouter);
app.route('/admin/cache', cacheRouter);
app.route('/admin', adminRouter);
app.route('/v1/notifications', notificationsRouter);
app.route('/v1/users', usersRouter);
app.route('/v1/alerts', alertsRouter);
app.route('/v1/ops', opsRouter);
app.route('/v2/nexus', nexusRoutes);
app.route('/v1/web-search', webSearchRoutes);
app.route('/v2/stream', streamRoutes);

// TAXII 2.1 server (OASIS standard for intelligence sharing)
app.route('/taxii2', taxiiRouter);

// SSE real-time events
app.route('/v2', sseRouter);

// WebSocket routes for real-time updates
import wsApp from './websocket';
app.route('', wsApp);

// GraphQL endpoint (Yoga + Pothos)
import { yoga } from './graphql';
app.on(['GET', 'POST'], '/graphql', async (c) => {
    const request = c.req.raw;
    const response = await yoga.handle(request);
    return new Response(response.body, {
        status: response.status,
        headers: response.headers,
    });
});

// ============================================================================
// Start Server (standalone mode only — skipped when imported by gateway)
// ============================================================================

const isStandalone = !process.env.GATEWAY_UNIFIED;

if (isStandalone) {
    // Validate auth config before starting (mandatory JWT_SECRET, etc.)
    try {
        validateAuthConfig();
    } catch (err) {
        console.error((err as Error).message);
        process.exit(1);
    }

    const port = parseInt(process.env.PORT || '3001', 10);

    log.info(`RinjaniAnalytics CTI API v1.0.0 starting`, { port, endpoints: { health: `/health`, v1: `/v1`, v2: `/v2`, docs: `/api-docs`, queues: `/admin/queues` } });

    serve({
        fetch: app.fetch,
        port,
        hostname: '0.0.0.0',
    });

    // Boot background services
    import('./startup').then(({ bootServices }) => bootServices());
}

export default app;

