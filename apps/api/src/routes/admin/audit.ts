/**
 * Admin Audit Log Routes
 *
 * Read-only endpoints for audit log inspection with filtering.
 * Queries the audit_logs table directly via Drizzle.
 *
 * Mounts at: /admin/audit/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { AdminAuditListSchema, AdminAuditStatsSchema } from '../../lib/schemas';
import { and, db, desc, eq, gte, lte, sql } from '@rinjani/db';
import { auditLogs } from '@rinjani/db/schema';

const router = new Hono();

// ============================================================================
// Audit Log List
// ============================================================================

/** GET /audit — List audit entries (paginated, filterable) */
router.get('/audit', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    const { entityType, action, from, to, page, limit } = AdminAuditListSchema.parse(c.req.query());
    const offset = (page - 1) * limit;

    const conditions = [];

    if (entityType) {
        conditions.push(eq(auditLogs.entityType, entityType as typeof auditLogs.entityType.enumValues[number]));
    }
    if (action) {
        conditions.push(sql`${auditLogs.action}::text = ${action}`);
    }
    if (from) {
        conditions.push(gte(auditLogs.createdAt, new Date(from)));
    }
    if (to) {
        conditions.push(lte(auditLogs.createdAt, new Date(to)));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const [rows, countResult] = await Promise.all([
        db.select().from(auditLogs).where(whereClause).orderBy(desc(auditLogs.createdAt)).limit(limit).offset(offset),
        db.select({ count: sql<number>`count(*)::int` }).from(auditLogs).where(whereClause),
    ]);

    return c.json({
        success: true,
        data: {
            entries: rows,
            total: countResult[0]?.count ?? 0,
            page,
            limit,
        },
    });
});

// ============================================================================
// Audit Stats (must be before :id route to avoid "stats" matching as UUID)
// ============================================================================

/** GET /audit/stats — Aggregated action/entity counts */
router.get('/audit/stats', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    const { days } = AdminAuditStatsSchema.parse(c.req.query());
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const [byAction, byEntity, total] = await Promise.all([
        db.select({
            action: auditLogs.action,
            count: sql<number>`count(*)::int`,
        }).from(auditLogs)
            .where(gte(auditLogs.createdAt, since))
            .groupBy(auditLogs.action),

        db.select({
            entityType: auditLogs.entityType,
            count: sql<number>`count(*)::int`,
        }).from(auditLogs)
            .where(gte(auditLogs.createdAt, since))
            .groupBy(auditLogs.entityType),

        db.select({ count: sql<number>`count(*)::int` })
            .from(auditLogs)
            .where(gte(auditLogs.createdAt, since)),
    ]);

    return c.json({
        success: true,
        data: {
            total: total[0]?.count ?? 0,
            days,
            byAction,
            byEntity,
        },
    });
});

// ============================================================================
// Audit Log Detail
// ============================================================================

/** GET /audit/:id — Single audit entry with full diff */
router.get('/audit/:id', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    const id = c.req.param('id')!; // route-guaranteed by :id pattern

    const rows = await db.select().from(auditLogs).where(eq(auditLogs.id, id)).limit(1);
    if (!rows[0]) {
        throw new NotFoundError('AuditEntry', id);
    }

    return c.json({ success: true, data: rows[0] });
});

export default router;
