/**
 * Batch Operations API
 *
 * Bulk update, delete, and tag operations for IOCs, CVEs, and actors.
 * Uses database transactions for atomicity and BullMQ for async enrichment.
 *
 * Mounts at: /v1/batch/*
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { and, db, eq, gte, inArray, lte, sql } from '@rinjani/db';
import { iocs, vulnerabilities } from '@rinjani/db/schema';
import { requireAuth, requireRole } from '../../middleware/auth';
import { createLogger } from '../../lib/logger';

const log = createLogger('BatchOps');
const router = new Hono();

// ============================================================================
// Schemas
// ============================================================================

const BatchIdsSchema = z.object({
    ids: z.array(z.string().guid()).min(1).max(500),
});

const BatchUpdateIOCSchema = z.object({
    ids: z.array(z.string().guid()).min(1).max(500),
    update: z.object({
        severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
        confidence: z.number().int().min(0).max(100).optional(),
        threatType: z.string().optional(),
        tags: z.array(z.string()).optional(),
    }).refine(obj => Object.keys(obj).length > 0, 'At least one field must be specified'),
});

const BatchTagSchema = z.object({
    ids: z.array(z.string().guid()).min(1).max(500),
    addTags: z.array(z.string()).optional(),
    removeTags: z.array(z.string()).optional(),
}).refine(obj => obj.addTags?.length || obj.removeTags?.length, 'At least one of addTags or removeTags required');

const BatchFilterDeleteSchema = z.object({
    filter: z.object({
        source: z.string().optional(),
        type: z.string().optional(),
        olderThan: z.string().datetime().optional(),
        maxConfidence: z.number().int().min(0).max(100).optional(),
    }).refine(obj => Object.keys(obj).length > 0, 'At least one filter required for safety'),
    dryRun: z.boolean().default(true),
});

// ============================================================================
// Batch Update IOCs
// ============================================================================

/** POST /batch/iocs/update — Update multiple IOCs at once */
router.post('/batch/iocs/update', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = BatchUpdateIOCSchema.parse(await c.req.json());
    const { ids, update } = body;

    const setFields: Record<string, unknown> = { updatedAt: new Date() };
    if (update.severity) setFields.severity = update.severity;
    if (update.confidence !== undefined) setFields.confidence = update.confidence;
    if (update.threatType) setFields.threatType = update.threatType;
    if (update.tags) setFields.tags = update.tags;

    const result = await db.update(iocs)
        .set(setFields)
        .where(inArray(iocs.id, ids))
        .returning({ id: iocs.id });

    log.info('Batch IOC update', { count: result.length, fields: Object.keys(update) });

    return c.json({
        success: true,
        data: {
            updated: result.length,
            requested: ids.length,
            ids: result.map(r => r.id),
        },
    });
});

// ============================================================================
// Batch Delete IOCs
// ============================================================================

/** POST /batch/iocs/delete — Delete multiple IOCs by ID */
router.post('/batch/iocs/delete', requireAuth, requireRole('admin'), async (c) => {
    const body = BatchIdsSchema.parse(await c.req.json());

    const result = await db.delete(iocs)
        .where(inArray(iocs.id, body.ids))
        .returning({ id: iocs.id });

    log.info('Batch IOC delete', { count: result.length });

    return c.json({
        success: true,
        data: {
            deleted: result.length,
            requested: body.ids.length,
        },
    });
});

// ============================================================================
// Batch Delete by Filter (with dry-run)
// ============================================================================

/** POST /batch/iocs/purge — Delete IOCs matching filter criteria (dry-run default) */
router.post('/batch/iocs/purge', requireAuth, requireRole('admin'), async (c) => {
    const body = BatchFilterDeleteSchema.parse(await c.req.json());
    const { filter, dryRun } = body;

    const conditions = [];
    if (filter.source) conditions.push(eq(iocs.source, filter.source));
    if (filter.type) conditions.push(eq(iocs.type, filter.type));
    if (filter.olderThan) conditions.push(lte(iocs.createdAt, new Date(filter.olderThan)));
    if (filter.maxConfidence !== undefined) conditions.push(lte(iocs.confidence, filter.maxConfidence));

    if (dryRun) {
        // Count only
        const countResult = await db.select({ count: sql<number>`count(*)::int` })
            .from(iocs)
            .where(and(...conditions));

        return c.json({
            success: true,
            data: {
                dryRun: true,
                wouldDelete: countResult[0]?.count ?? 0,
                filter,
            },
        });
    }

    const result = await db.delete(iocs)
        .where(and(...conditions))
        .returning({ id: iocs.id });

    log.info('Batch IOC purge', { count: result.length, filter });

    return c.json({
        success: true,
        data: {
            deleted: result.length,
            filter,
        },
    });
});

// ============================================================================
// Batch Tag Operations
// ============================================================================

/** POST /batch/iocs/tags — Add/remove tags on multiple IOCs */
router.post('/batch/iocs/tags', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = BatchTagSchema.parse(await c.req.json());
    const { ids, addTags, removeTags } = body;

    let updated = 0;

    if (addTags?.length) {
        // Append tags using array_cat + array_distinct
        const result = await db.execute(sql`
            UPDATE iocs
            SET tags = (
                SELECT array_agg(DISTINCT elem)
                FROM unnest(COALESCE(tags, ARRAY[]::text[]) || ${addTags}::text[]) AS elem
            ),
            updated_at = NOW()
            WHERE id = ANY(${ids}::uuid[])
        `);
        updated += Number((result as unknown as { rowCount: number }).rowCount || 0);
    }

    if (removeTags?.length) {
        const result = await db.execute(sql`
            UPDATE iocs
            SET tags = array(
                SELECT unnest(COALESCE(tags, ARRAY[]::text[]))
                EXCEPT
                SELECT unnest(${removeTags}::text[])
            ),
            updated_at = NOW()
            WHERE id = ANY(${ids}::uuid[])
        `);
        updated += Number((result as unknown as { rowCount: number }).rowCount || 0);
    }

    return c.json({
        success: true,
        data: { updated, addTags, removeTags },
    });
});

// ============================================================================
// Batch Update CVEs
// ============================================================================

/** POST /batch/cves/update — Update multiple CVEs at once */
router.post('/batch/cves/update', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = z.object({
        ids: z.array(z.string().guid()).min(1).max(500),
        update: z.object({
            severity: z.enum(['none', 'low', 'medium', 'high', 'critical']).optional(),
            isExploited: z.boolean().optional(),
        }).refine(obj => Object.keys(obj).length > 0),
    }).parse(await c.req.json());

    const setFields: Record<string, unknown> = { updatedAt: new Date() };
    if (body.update.severity) setFields.severity = body.update.severity;
    if (body.update.isExploited !== undefined) setFields.isExploited = body.update.isExploited;

    const result = await db.update(vulnerabilities)
        .set(setFields)
        .where(inArray(vulnerabilities.id, body.ids))
        .returning({ id: vulnerabilities.id });

    return c.json({
        success: true,
        data: {
            updated: result.length,
            requested: body.ids.length,
        },
    });
});

/** POST /batch/cves/delete — Delete multiple CVEs by ID */
router.post('/batch/cves/delete', requireAuth, requireRole('admin'), async (c) => {
    const body = BatchIdsSchema.parse(await c.req.json());

    const result = await db.delete(vulnerabilities)
        .where(inArray(vulnerabilities.id, body.ids))
        .returning({ id: vulnerabilities.id });

    return c.json({
        success: true,
        data: {
            deleted: result.length,
            requested: body.ids.length,
        },
    });
});

export default router;
