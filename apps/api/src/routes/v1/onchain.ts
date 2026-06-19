/**
 * /v1/onchain — on-chain entity model (AA.6.1 / PLAN Phase 8, follow-the-money).
 *
 *   wallets/   crypto addresses + CONFIDENCE-WEIGHTED attribution.
 *
 * POST (upsert by ref_id) · GET list (filter + q) · GET :id · DELETE :id.
 * Reads open to any authenticated user; writes require admin/analyst/developer.
 * Mirrors /v1/telco. Live attribution comes from the free multi-source lookup
 * (services/onchainLookup.ts): our DB + Blockscout + DefiLlama + optional
 * MistTrack. No paid Arkham dependency.
 *
 * Invariant: attribution is a CLAIM — entity_label/entity_type ride with a
 * confidence (0–100) and a source. Never asserted as fact.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import { upsertWallet, listWallets, getWallet, deleteWallet, walletStats } from '../../services/onchainStore';

const log = createLogger('OnChain');
const router = new Hono();
const WRITE_ROLES = ['admin', 'analyst', 'developer'] as const;

router.use('*', requireAuth);

function parseOrThrow<T>(schema: z.ZodType<T>, raw: unknown): T {
    const parsed = schema.safeParse(raw);
    if (!parsed.success) {
        throw new ValidationError('Invalid request body', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }
    return parsed.data;
}

const jsonStrArray = z.array(z.string()).default([]);
const jsonObjArray = z.array(z.record(z.unknown())).default([]);

const WalletBody = z.object({
    refId: z.string().min(1).max(255),
    address: z.string().min(1).max(255),
    chain: z.string().min(1).max(32),
    name: z.string().max(500).optional(),
    description: z.string().optional(),
    stixId: z.string().max(255).optional(),
    entityLabel: z.string().max(255).optional(),
    entityType: z.string().max(64).optional(),
    // CONFIDENCE-WEIGHTED — defaults to 50 ("no strong signal") when omitted.
    confidence: z.number().int().min(0).max(100).default(50),
    attributionSource: z.string().max(64).optional(),
    riskTags: jsonStrArray,
    externalReferences: jsonObjArray,
    labels: jsonStrArray,
});

router.post('/onchain/wallets', requireRole(...WRITE_ROLES), async (c) => {
    const body = parseOrThrow(WalletBody, await c.req.json().catch(() => ({})));
    const row = await upsertWallet(body);
    log.info('Wallet upserted', { id: row.id, refId: row.refId, confidence: row.confidence });
    return c.json({ success: true, data: row }, 201);
});

router.get('/onchain/wallets', async (c) => {
    const rows = await listWallets({
        chain: c.req.query('chain'),
        entityType: c.req.query('entityType'),
        q: c.req.query('q'),
        riskTag: c.req.query('riskTag'),
        limit: c.req.query('limit') ? Number(c.req.query('limit')) : undefined,
    });
    return c.json({ success: true, data: rows, count: rows.length });
});

// Category aggregates (total + by entity_type + by attribution_source). The
// list endpoint caps at 500 rows so the dashboard can't count scam (~2.5k) or
// defi accurately — this GROUP BY does. Registered before `:id` so "stats" is
// not captured as a wallet id.
router.get('/onchain/wallets/stats', async (c) => {
    return c.json({ success: true, data: await walletStats() });
});

router.get('/onchain/wallets/:id', async (c) => {
    const { id } = c.req.param();
    const row = await getWallet(id);
    if (!row) throw new NotFoundError('Wallet', id);
    return c.json({ success: true, data: row });
});

router.delete('/onchain/wallets/:id', requireRole(...WRITE_ROLES), async (c) => {
    const { id } = c.req.param();
    const ok = await deleteWallet(id);
    if (!ok) throw new NotFoundError('Wallet', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

export default router;
