/**
 * Dark-web monitoring (Ahmia) routes — Phase 5 #4.
 *
 *   POST   /v1/dark-web/watchterms              Add a search term
 *   GET    /v1/dark-web/watchterms              List
 *   GET    /v1/dark-web/watchterms/:id          Detail
 *   PATCH  /v1/dark-web/watchterms/:id          Update enabled / kind / owner
 *   DELETE /v1/dark-web/watchterms/:id          Remove (cascades mentions)
 *   POST   /v1/dark-web/watchterms/:id/scan    Run a one-off Ahmia query
 *   POST   /v1/dark-web/scan                   Sweep all enabled watchterms
 *   GET    /v1/dark-web/mentions                Triage queue
 *   PATCH  /v1/dark-web/mentions/:id           Lifecycle update
 *
 * Strict scope: Ahmia clearnet search index only. NO .onion crawling.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    DarkWebWatchtermCreateSchema, DarkWebWatchtermUpdateSchema,
    DarkWebMentionListSchema, DarkWebMentionUpdateSchema,
} from '../../lib/schemas';
import { db, eq, and, desc, sql } from '@rinjani/db';
import { darkWebWatchterms, darkWebMentions } from '@rinjani/db/schema';
import { scanWatchterm, scanAllWatchterms } from '../../services/ahmiaSearch';
import { createLogger } from '../../lib/logger';

const log = createLogger('DarkWebRoutes');
const router = new Hono();

// ── Watchterm CRUD ────────────────────────────────────────────────

router.post('/dark-web/watchterms', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = DarkWebWatchtermCreateSchema.parse(await c.req.json());
    const userId = c.get('user')?.id || 'unknown';
    try {
        const [row] = await db.insert(darkWebWatchterms).values({
            term: body.term,
            kind: body.kind ?? null,
            owner: body.owner ?? null,
            enabled: body.enabled,
            createdBy: userId,
        }).returning();
        log.info('Dark-web watchterm added', { id: row.id, term: row.term });
        return c.json({ success: true, data: row }, 201);
    } catch (err) {
        const e = err as { code?: string };
        if (e.code === '23505') {
            return c.json({
                success: false,
                error: { code: 'CONFLICT', message: `term "${body.term}" already watched` },
            }, 409);
        }
        throw err;
    }
});

router.get('/dark-web/watchterms', requireAuth, async (c) => {
    const rows = await db.select().from(darkWebWatchterms).orderBy(darkWebWatchterms.term);
    return c.json({ success: true, data: rows });
});

router.get('/dark-web/watchterms/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const [row] = await db.select().from(darkWebWatchterms).where(eq(darkWebWatchterms.id, id)).limit(1);
    if (!row) throw new NotFoundError('Dark-web watchterm', id);
    const recent = await db.select().from(darkWebMentions)
        .where(eq(darkWebMentions.watchtermId, id))
        .orderBy(desc(darkWebMentions.lastSeenAt))
        .limit(20);
    return c.json({ success: true, data: { ...row, recentMentions: recent } });
});

router.patch('/dark-web/watchterms/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = DarkWebWatchtermUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.kind !== undefined) patch.kind = body.kind;
    if (body.owner !== undefined) patch.owner = body.owner;
    if (body.enabled !== undefined) patch.enabled = body.enabled;
    const [row] = await db.update(darkWebWatchterms).set(patch).where(eq(darkWebWatchterms.id, id)).returning();
    if (!row) throw new NotFoundError('Dark-web watchterm', id);
    return c.json({ success: true, data: row });
});

router.delete('/dark-web/watchterms/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id')!;
    const result = await db.delete(darkWebWatchterms).where(eq(darkWebWatchterms.id, id)).returning({ id: darkWebWatchterms.id });
    if (result.length === 0) throw new NotFoundError('Dark-web watchterm', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// ── Scan ──────────────────────────────────────────────────────────

router.post('/dark-web/watchterms/:id/scan', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    try {
        const r = await scanWatchterm(id);
        return c.json({ success: true, data: r });
    } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes('not found')) throw new NotFoundError('Dark-web watchterm', id);
        throw err;
    }
});

router.post('/dark-web/scan', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const summary = await scanAllWatchterms();
    return c.json({ success: true, data: summary });
});

// ── Mentions ──────────────────────────────────────────────────────

router.get('/dark-web/mentions', requireAuth, async (c) => {
    const f = DarkWebMentionListSchema.parse(c.req.query());
    const conds = [];
    if (f.watchtermId) conds.push(eq(darkWebMentions.watchtermId, f.watchtermId));
    if (f.status) conds.push(eq(darkWebMentions.status, f.status));
    if (typeof f.minScore === 'number') conds.push(sql`${darkWebMentions.score} >= ${f.minScore}`);
    const where = conds.length === 0 ? undefined : conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select().from(darkWebMentions)
            .where(where ?? sql`true`)
            .orderBy(desc(darkWebMentions.score), desc(darkWebMentions.lastSeenAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(darkWebMentions).where(where ?? sql`true`),
    ]);
    return c.json({
        success: true,
        data: {
            items,
            pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
        },
    });
});

router.patch('/dark-web/mentions/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = DarkWebMentionUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.status !== undefined) patch.status = body.status;
    if (body.notes !== undefined) patch.notes = body.notes;
    const [row] = await db.update(darkWebMentions).set(patch).where(eq(darkWebMentions.id, id)).returning();
    if (!row) throw new NotFoundError('Dark-web mention', id);
    return c.json({ success: true, data: row });
});

export default router;
