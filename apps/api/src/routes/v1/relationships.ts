/**
 * IOC Relationship Management — STIX SRO inspired
 *
 * Explicit bidirectional links between entities.
 * Relationship types follow STIX 2.1 SRO vocabulary.
 *
 * Mounts at: /v1/relationships/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import {
    CreateRelationshipSchema, BulkRelationshipSchema,
    RelationshipFilterSchema,
} from '../../lib/schemas';

const log = createLogger('Relationships');
const router = new Hono();
router.use('*', requireAuth);

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        // The `relationships` table is created by the MITRE sync schema.
        // Just ensure indexes exist for the entity_relationships queries.
        await rawQuery(sql.raw(`
            CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_type, source_id);
            CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_type, target_id);
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// POST /relationships
router.post('/relationships', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const body = CreateRelationshipSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const result = await rawQuery(sql.raw(`
        INSERT INTO relationships (source_type, source_id, target_type, target_id, relationship_type, confidence, description, created_by)
        VALUES ('${esc(body.sourceType)}', '${esc(body.sourceId)}', '${esc(body.targetType)}', '${esc(body.targetId)}',
                '${esc(body.relationshipType)}', ${body.confidence},
                ${body.description ? `'${esc(body.description)}'` : 'NULL'}, '${esc(userId)}')
        ON CONFLICT (source_type, source_id, target_type, target_id, relationship_type) DO UPDATE SET
            confidence = EXCLUDED.confidence, description = EXCLUDED.description
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// GET /relationships
router.get('/relationships', async (c) => {
    await ensureOnce();
    const { page, pageSize, sourceType, targetType, relationshipType, entityId } = RelationshipFilterSchema.parse(c.req.query());
    const conds: string[] = ['1=1'];
    if (sourceType) conds.push(`source_type = '${esc(sourceType)}'`);
    if (targetType) conds.push(`target_type = '${esc(targetType)}'`);
    if (relationshipType) conds.push(`relationship_type = '${esc(relationshipType)}'`);
    if (entityId) conds.push(`(source_id = '${esc(entityId)}' OR target_id = '${esc(entityId)}')`);
    const where = conds.join(' AND ');
    const offset = (page - 1) * pageSize;
    const [items, cnt] = await Promise.all([
        rawQuery(sql.raw(`SELECT * FROM relationships WHERE ${where} ORDER BY created_at DESC LIMIT ${pageSize} OFFSET ${offset}`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM relationships WHERE ${where}`)),
    ]);
    const total = Number((cnt.rows?.[0] as Record<string, unknown>)?.total || 0);
    return c.json({ success: true, data: { items: items.rows || [], pagination: { page, pageSize, total, pages: Math.ceil(total / pageSize) } } });
});

// GET /relationships/:id
router.get('/relationships/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`SELECT * FROM relationships WHERE id = '${esc(id)}'`));
    if (!result.rows?.[0]) throw new NotFoundError('Relationship', id);
    return c.json({ success: true, data: result.rows[0] });
});

// DELETE /relationships/:id
router.delete('/relationships/:id', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM relationships WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('Relationship', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// GET /entities/:id/relationships
router.get('/entities/:id/relationships', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`
        SELECT * FROM relationships
        WHERE source_id = '${esc(id)}' OR target_id = '${esc(id)}'
        ORDER BY created_at DESC LIMIT 100
    `));
    const rows = (result.rows || []) as Array<Record<string, unknown>>;
    return c.json({
        success: true,
        data: {
            entityId: id,
            outgoing: rows.filter(r => r.source_id === id),
            incoming: rows.filter(r => r.target_id === id),
            total: rows.length,
        },
    });
});

// POST /relationships/bulk
router.post('/relationships/bulk', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const body = BulkRelationshipSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    let created = 0;
    for (const rel of body.relationships) {
        try {
            await rawQuery(sql.raw(`
                INSERT INTO relationships (source_type, source_id, target_type, target_id, relationship_type, confidence, description, created_by)
                VALUES ('${esc(rel.sourceType)}', '${esc(rel.sourceId)}', '${esc(rel.targetType)}', '${esc(rel.targetId)}',
                        '${esc(rel.relationshipType)}', ${rel.confidence},
                        ${rel.description ? `'${esc(rel.description)}'` : 'NULL'}, '${esc(userId)}')
                ON CONFLICT (source_type, source_id, target_type, target_id, relationship_type) DO UPDATE SET
                    confidence = EXCLUDED.confidence, description = EXCLUDED.description
            `));
            created++;
        } catch (err) {
            log.warn('Bulk relationship insert error', { error: (err as Error).message });
        }
    }
    return c.json({ success: true, data: { requested: body.relationships.length, created } });
});

export default router;
