/**
 * Paste-site monitoring routes — Phase 5 #5.
 *
 *   POST   /v1/paste/watchterms              Add a search term
 *   GET    /v1/paste/watchterms              List
 *   GET    /v1/paste/watchterms/:id          Detail + recent mentions
 *   PATCH  /v1/paste/watchterms/:id          Update
 *   DELETE /v1/paste/watchterms/:id          Remove (cascades)
 *   POST   /v1/paste/scan                   Ad-hoc Gist firehose scan
 *   GET    /v1/paste/mentions                Triage queue
 *   PATCH  /v1/paste/mentions/:id           Analyst lifecycle
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    PasteWatchtermCreateSchema, PasteWatchtermUpdateSchema,
    PasteMentionListSchema, PasteMentionUpdateSchema,
} from '../../lib/schemas';
import { db, eq, and, desc, sql } from '@rinjani/db';
import { pasteWatchterms, pasteMentions } from '@rinjani/db/schema';
import { runGistScan } from '../../services/gistMonitor';
import { createLogger } from '../../lib/logger';

const log = createLogger('PasteRoutes');
const router = new Hono();

router.post('/paste/watchterms', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = PasteWatchtermCreateSchema.parse(await c.req.json());
    const userId = c.get('user')?.id || 'unknown';
    try {
        const [row] = await db.insert(pasteWatchterms).values({
            term: body.term,
            kind: body.kind ?? null,
            owner: body.owner ?? null,
            enabled: body.enabled,
            createdBy: userId,
        }).returning();
        log.info('Paste watchterm added', { id: row.id, term: row.term });
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

router.get('/paste/watchterms', requireAuth, async (c) => {
    const rows = await db.select().from(pasteWatchterms).orderBy(pasteWatchterms.term);
    return c.json({ success: true, data: rows });
});

router.get('/paste/watchterms/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const [row] = await db.select().from(pasteWatchterms).where(eq(pasteWatchterms.id, id)).limit(1);
    if (!row) throw new NotFoundError('Paste watchterm', id);
    const recent = await db.select().from(pasteMentions)
        .where(eq(pasteMentions.watchtermId, id))
        .orderBy(desc(pasteMentions.lastSeenAt))
        .limit(20);
    return c.json({ success: true, data: { ...row, recentMentions: recent } });
});

router.patch('/paste/watchterms/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = PasteWatchtermUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.kind !== undefined) patch.kind = body.kind;
    if (body.owner !== undefined) patch.owner = body.owner;
    if (body.enabled !== undefined) patch.enabled = body.enabled;
    const [row] = await db.update(pasteWatchterms).set(patch).where(eq(pasteWatchterms.id, id)).returning();
    if (!row) throw new NotFoundError('Paste watchterm', id);
    return c.json({ success: true, data: row });
});

router.delete('/paste/watchterms/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id')!;
    const result = await db.delete(pasteWatchterms).where(eq(pasteWatchterms.id, id)).returning({ id: pasteWatchterms.id });
    if (result.length === 0) throw new NotFoundError('Paste watchterm', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

router.post('/paste/scan', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const summary = await runGistScan();
    return c.json({ success: true, data: summary });
});

router.get('/paste/mentions', requireAuth, async (c) => {
    const f = PasteMentionListSchema.parse(c.req.query());
    const conds = [];
    if (f.watchtermId) conds.push(eq(pasteMentions.watchtermId, f.watchtermId));
    if (f.status) conds.push(eq(pasteMentions.status, f.status));
    if (typeof f.minScore === 'number') conds.push(sql`${pasteMentions.score} >= ${f.minScore}`);
    const where = conds.length === 0 ? undefined : conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select().from(pasteMentions)
            .where(where ?? sql`true`)
            .orderBy(desc(pasteMentions.score), desc(pasteMentions.lastSeenAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(pasteMentions).where(where ?? sql`true`),
    ]);
    return c.json({
        success: true,
        data: {
            items,
            pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
        },
    });
});

router.patch('/paste/mentions/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = PasteMentionUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.status !== undefined) patch.status = body.status;
    if (body.notes !== undefined) patch.notes = body.notes;
    const [row] = await db.update(pasteMentions).set(patch).where(eq(pasteMentions.id, id)).returning();
    if (!row) throw new NotFoundError('Paste mention', id);
    return c.json({ success: true, data: row });
});

export default router;
