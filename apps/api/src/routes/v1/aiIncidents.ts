/**
 * /v1/ai-incidents — the AI-threat-landscape vertical.
 *
 *   GET /ai-incidents        list (filter: q, since, limit)
 *   GET /ai-incidents/stats  total + monthly timeline + top developers (trend)
 *
 * Read-only: rows are feed-ingested from the AI Incident Database
 * (incidentdatabase.ai) — there is no operator write path. Mirrors /v1/onchain
 * + /v1/telco. Reads open to any authenticated user.
 */

import { Hono } from 'hono';
import { requireAuth } from '../../middleware/auth';
import { listAiIncidents, aiIncidentStats } from '../../services/aiIncidentStore';

const router = new Hono();
router.use('*', requireAuth);

router.get('/ai-incidents/stats', async (c) => {
    const months = Number(c.req.query('months')) || 24;
    const g = c.req.query('granularity');
    const granularity = g === 'day' || g === 'week' ? g : 'month';
    const stats = await aiIncidentStats(months, granularity);
    return c.json({ success: true, data: stats });
});

router.get('/ai-incidents', async (c) => {
    const rows = await listAiIncidents({
        q: c.req.query('q') || undefined,
        since: c.req.query('since') || undefined,
        limit: Number(c.req.query('limit')) || undefined,
        sort: c.req.query('sort') === 'date' ? 'date' : 'recency',
    });
    return c.json({ success: true, data: rows, count: rows.length });
});

export default router;
