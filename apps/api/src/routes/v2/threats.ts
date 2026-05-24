/**
 * V2 Threats & Indicators (stub endpoints)
 */

import { Hono } from 'hono';

// =============================================================================
// Threats
// =============================================================================

export const threatRoutes = new Hono();

threatRoutes.get('/', async (c) => {
    const { page, pageSize } = (await import('../../lib/schemas')).PaginationSchema.parse(c.req.query());

    return c.json({
        success: true,
        data: {
            items: [],
            pagination: { page, pageSize, total: 0, pages: 0, hasNext: false, hasPrev: false },
        },
        meta: { requestId: crypto.randomUUID(), took: 0 },
    });
});

threatRoutes.get('/:id', async (c) => {
    const { id } = c.req.param();
    return c.json({
        success: true,
        data: { id, name: 'Placeholder', type: 'threat-actor' },
        meta: { requestId: crypto.randomUUID() },
    });
});

// =============================================================================
// Indicators
// =============================================================================

export const indicatorRoutes = new Hono();

indicatorRoutes.get('/', async (c) => {
    const { page, pageSize } = (await import('../../lib/schemas')).PaginationSchema.parse(c.req.query());

    return c.json({
        success: true,
        data: {
            items: [],
            pagination: { page, pageSize, total: 0, pages: 0, hasNext: false, hasPrev: false },
        },
        meta: { requestId: crypto.randomUUID(), took: 0 },
    });
});

indicatorRoutes.post('/lookup', async (c) => {
    const body = await c.req.json();
    const values = body.values || [];

    return c.json({
        success: true,
        data: {
            matches: Object.fromEntries(values.map((v: string) => [v, null])),
        },
        meta: { requestId: crypto.randomUUID() },
    });
});
