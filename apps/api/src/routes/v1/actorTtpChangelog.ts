/**
 * Threat-actor TTP changelog routes — Phase 5 #2.
 *
 *   GET    /v1/ttp-changes                     Global change log (filter + paginate)
 *   GET    /v1/actors/:actorId/ttp-changes     Per-actor change log
 *   POST   /v1/ttp-changes/run-diff            Ad-hoc differ trigger (admin)
 *
 * The differ also runs automatically every day at 04:30 UTC after the
 * MITRE sync — see scheduler entry `mitreTtpDiff`.
 *
 * The list endpoints LEFT JOIN against `threat_actors.real_stix_id` and
 * `techniques.real_stix_id` to resolve human-readable names alongside the
 * raw STIX IDs the differ stores. JOINs are LEFT so rows where the catalog
 * hasn't caught up (e.g. a freshly-ingested relationship whose actor/
 * technique row hasn't been upserted yet) still render with the raw IDs
 * instead of being filtered out.
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { TtpChangeListSchema } from '../../lib/schemas';
import { db, eq, and, desc, sql } from '@rinjani/db';
import { actorTtpChanges, threatActors, techniques } from '@rinjani/db/schema';
import { runActorTtpDiff } from '../../services/actorTtpDiffer';

const router = new Hono();

// ── Read ──────────────────────────────────────────────────────────

// Shared SELECT shape: the raw differ row plus three resolved fields.
// Aliases are returned as `actor_aliases` (jsonb array) — useful when an
// analyst recognises an alias but not the canonical MITRE name.
const SELECT_SHAPE = {
    id: actorTtpChanges.id,
    actorId: actorTtpChanges.actorId,
    techniqueId: actorTtpChanges.techniqueId,
    changeType: actorTtpChanges.changeType,
    detectedAt: actorTtpChanges.detectedAt,
    note: actorTtpChanges.note,
    actorName: threatActors.name,
    actorAliases: threatActors.aliases,
    techniqueMitreId: techniques.mitreId,
    techniqueName: techniques.name,
};

router.get('/ttp-changes', requireAuth, async (c) => {
    const f = TtpChangeListSchema.parse(c.req.query());
    const conds = [];
    if (f.actorId) conds.push(eq(actorTtpChanges.actorId, f.actorId));
    if (f.techniqueId) conds.push(eq(actorTtpChanges.techniqueId, f.techniqueId));
    if (f.changeType) conds.push(eq(actorTtpChanges.changeType, f.changeType));
    if (f.since) conds.push(sql`${actorTtpChanges.detectedAt} >= ${new Date(f.since)}`);
    const where = conds.length === 0 ? undefined : conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select(SELECT_SHAPE).from(actorTtpChanges)
            .leftJoin(threatActors, eq(threatActors.realStixId, actorTtpChanges.actorId))
            .leftJoin(techniques, eq(techniques.realStixId, actorTtpChanges.techniqueId))
            .where(where ?? sql`true`)
            .orderBy(desc(actorTtpChanges.detectedAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(actorTtpChanges).where(where ?? sql`true`),
    ]);
    return c.json({
        success: true,
        data: {
            items,
            pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
        },
    });
});

router.get('/actors/:actorId/ttp-changes', requireAuth, async (c) => {
    const actorId = c.req.param('actorId')!;
    const f = TtpChangeListSchema.parse({ ...c.req.query(), actorId });
    const conds = [eq(actorTtpChanges.actorId, actorId)];
    if (f.changeType) conds.push(eq(actorTtpChanges.changeType, f.changeType));
    if (f.since) conds.push(sql`${actorTtpChanges.detectedAt} >= ${new Date(f.since)}`);
    const where = conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select(SELECT_SHAPE).from(actorTtpChanges)
            .leftJoin(threatActors, eq(threatActors.realStixId, actorTtpChanges.actorId))
            .leftJoin(techniques, eq(techniques.realStixId, actorTtpChanges.techniqueId))
            .where(where ?? sql`true`)
            .orderBy(desc(actorTtpChanges.detectedAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(actorTtpChanges).where(where ?? sql`true`),
    ]);
    return c.json({
        success: true,
        data: {
            items,
            pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
        },
    });
});

// ── Ad-hoc run ────────────────────────────────────────────────────

router.post('/ttp-changes/run-diff', requireAuth, requireRole('admin'), async (c) => {
    const summary = await runActorTtpDiff();
    return c.json({ success: true, data: summary });
});

export default router;
