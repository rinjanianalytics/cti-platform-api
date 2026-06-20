/**
 * Graph-first SIEM hunt (PLAN Track-B B3 / Phase 9–10).
 *
 *   POST /v1/hunt — NL→Cypher expands an indicator set from the graph, a
 *   read-only Lucene query is synthesized and fired at the SIEM, and the
 *   indicators that show up in telemetry are correlated back.
 *
 * Fully read-only + deterministic. Writing the result into hypothesis tracking
 * is a separate, explicit HITL action (agent `hypo.proposeEvidence`).
 */
import { Hono } from 'hono';
import { z } from 'zod';
import { requireAuth } from '../../middleware/auth';
import { graphFirstHunt } from '../../services/graphFirstHunt';

const router = new Hono();
router.use('*', requireAuth);

const HuntSchema = z.object({
    question: z.string().min(3).max(500),
    seedIndicators: z.array(z.string().min(1).max(512)).max(100).optional(),
    index: z.string().max(128).optional(),
    sinceHours: z.coerce.number().int().min(1).max(720).optional(),
    size: z.coerce.number().int().min(1).max(100).optional(),
});

router.post('/hunt', async (c) => {
    const body = HuntSchema.parse(await c.req.json().catch(() => ({})));
    const result = await graphFirstHunt(body);
    return c.json({ success: true, data: result });
});

export default router;
