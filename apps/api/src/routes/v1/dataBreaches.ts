/**
 * HIBP breach catalog routes — Phase 5 #3.
 *
 *   GET    /v1/data-breaches             List + filter (domain / since / hide-spam / hide-retired)
 *   GET    /v1/data-breaches/:name        Detail by HIBP canonical name
 *   POST   /v1/data-breaches/sync        Admin-only ad-hoc sync trigger
 *
 * The catalog also refreshes daily at 06:30 UTC via the existing
 * feed-sync scheduler entry — see `hibpSync` in queues/scheduler.ts.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { DataBreachListSchema } from '../../lib/schemas';
import { db, eq, and, desc, sql } from '@rinjani/db';
import { dataBreaches } from '@rinjani/db/schema';
import { syncHibpBreaches } from '../../services/feedSync/hibpSync';

const router = new Hono();

router.get('/data-breaches', requireAuth, async (c) => {
    const f = DataBreachListSchema.parse(c.req.query());
    const conds = [];
    if (f.domain) conds.push(sql`LOWER(${dataBreaches.domain}) = LOWER(${f.domain})`);
    if (f.name) conds.push(eq(dataBreaches.name, f.name));
    if (f.addedSince) conds.push(sql`${dataBreaches.addedDate} >= ${new Date(f.addedSince)}`);
    if (f.breachSince) conds.push(sql`${dataBreaches.breachDate} >= ${new Date(f.breachSince)}`);
    if (!f.includeRetired) conds.push(eq(dataBreaches.isRetired, false));
    if (!f.includeSpamList) conds.push(eq(dataBreaches.isSpamList, false));
    if (!f.includeFabricated) conds.push(eq(dataBreaches.isFabricated, false));
    const where = conds.length === 0 ? undefined : conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select({
            id: dataBreaches.id,
            name: dataBreaches.name,
            title: dataBreaches.title,
            domain: dataBreaches.domain,
            breachDate: dataBreaches.breachDate,
            addedDate: dataBreaches.addedDate,
            modifiedDate: dataBreaches.modifiedDate,
            pwnCount: dataBreaches.pwnCount,
            dataClasses: dataBreaches.dataClasses,
            isVerified: dataBreaches.isVerified,
            isSensitive: dataBreaches.isSensitive,
            isRetired: dataBreaches.isRetired,
            logoPath: dataBreaches.logoPath,
        }).from(dataBreaches)
            .where(where ?? sql`true`)
            .orderBy(desc(dataBreaches.addedDate))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(dataBreaches).where(where ?? sql`true`),
    ]);

    return c.json({
        success: true,
        data: {
            items,
            pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
        },
    });
});

router.get('/data-breaches/:name', requireAuth, async (c) => {
    const name = c.req.param('name')!;
    const [row] = await db.select().from(dataBreaches).where(eq(dataBreaches.name, name)).limit(1);
    if (!row) throw new NotFoundError('Data breach', name);
    return c.json({ success: true, data: row });
});

router.post('/data-breaches/sync', requireAuth, requireRole('admin'), async (c) => {
    const result = await syncHibpBreaches();
    return c.json({
        success: result.success,
        data: {
            totalEntries: result.indicatorsProcessed,
            added: result.indicatorsAdded,
            updated: result.indicatorsUpdated,
            errors: result.errors,
        },
    }, result.success ? 200 : 502);
});

export default router;
