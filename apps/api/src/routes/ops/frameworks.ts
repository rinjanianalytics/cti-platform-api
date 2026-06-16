/**
 * Ops — MITRE FiGHT + ATLAS ingestion (FW.2).
 *
 * POST /v1/ops/frameworks/sync — download the upstream FiGHT/ATLAS YAML and
 * upsert into the fight_ and atlas_ tables (replaces the Python seed scripts).
 * Admin-only; idempotent. After this, a `frameworks` neo4j-sync projects the
 * techniques into the graph for the agent to hunt.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { ingestFrameworks, ingestAtlas, ingestFight } from '../../services/frameworkIngest';
import { createLogger } from '../../lib/logger';

const router = new Hono();
const log = createLogger('Ops');

router.post('/frameworks/sync', requireAuth, requireRole('admin'), async (c) => {
    const which = c.req.query('only'); // 'atlas' | 'fight' | undefined (both)
    try {
        const data = which === 'atlas' ? { atlas: await ingestAtlas() }
            : which === 'fight' ? { fight: await ingestFight() }
            : await ingestFrameworks();
        log.info('frameworks ingested', { which: which ?? 'both' });
        return c.json({ success: true, data });
    } catch (err) {
        const message = (err as Error).message;
        log.error('frameworks ingest failed', { error: message });
        return c.json({ success: false, error: { code: 'INGEST_ERROR', message } }, 500);
    }
});

export default router;
