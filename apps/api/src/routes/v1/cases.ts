/**
 * Case / Investigation Management Routes (TheHive inspired)
 *
 * Full investigation lifecycle:
 *   - Create, list, update, close cases
 *   - Attach observables (IOCs, CVEs, threat actors)
 *   - Manage investigation tasks
 *   - Timeline / activity log
 *   - Create case from escalated alert
 *
 * Mounts at: /v1/cases/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import {
    CreateCaseSchema, UpdateCaseSchema, CaseFilterSchema,
    CaseObservableSchema, CaseTaskSchema, UpdateCaseTaskSchema,
    CaseTimelineSchema, CaseFromAlertSchema,
} from '../../lib/schemas';
import { alertStore } from '../../queues/workers';

const log = createLogger('Cases');
const cases = new Hono();
cases.use('*', requireAuth);

// ============================================================================
// Auto-create Tables
// ============================================================================

const ensureTablesOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'open',
                assignee TEXT,
                tlp TEXT NOT NULL DEFAULT 'green',
                tags TEXT[] DEFAULT '{}',
                resolution TEXT,
                created_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS case_observables (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                notes TEXT,
                tags TEXT[] DEFAULT '{}',
                added_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(case_id, entity_type, entity_id)
            );
            CREATE TABLE IF NOT EXISTS case_tasks (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'todo',
                assignee TEXT,
                due_date TIMESTAMPTZ,
                created_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS case_timeline (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                entry_type TEXT NOT NULL DEFAULT 'comment',
                content TEXT NOT NULL,
                created_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// ============================================================================
// POST /cases — Create investigation case
// ============================================================================

cases.post('/cases', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const body = CreateCaseSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    const result = await rawQuery(sql.raw(`
        INSERT INTO cases (title, description, severity, status, assignee, tlp, tags, created_by)
        VALUES ('${esc(body.title)}', ${body.description ? `'${esc(body.description)}'` : 'NULL'},
                '${esc(body.severity)}', '${esc(body.status)}', ${body.assignee ? `'${esc(body.assignee)}'` : 'NULL'},
                '${esc(body.tlp)}', ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}], '${esc(userId)}')
        RETURNING *
    `));

    const row = result.rows?.[0];
    log.info('Case created', { caseId: row?.id, title: body.title });
    return c.json({ success: true, data: row }, 201);
});

// ============================================================================
// GET /cases — List cases with filters
// ============================================================================

cases.get('/cases', async (c) => {
    await ensureTablesOnce();
    const { page, pageSize, status, severity, assignee, q } = CaseFilterSchema.parse(c.req.query());

    const conditions: string[] = ['1=1'];
    if (status) conditions.push(`status = '${esc(status)}'`);
    if (severity) conditions.push(`severity = '${esc(severity)}'`);
    if (assignee) conditions.push(`assignee = '${esc(assignee)}'`);
    if (q) conditions.push(`(title ILIKE '%${esc(q)}%' OR description ILIKE '%${esc(q)}%')`);

    const where = conditions.join(' AND ');
    const offset = (page - 1) * pageSize;

    const [items, countResult] = await Promise.all([
        rawQuery(sql.raw(`SELECT * FROM cases WHERE ${where} ORDER BY updated_at DESC LIMIT ${pageSize} OFFSET ${offset}`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM cases WHERE ${where}`)),
    ]);

    const total = parseInt(String((countResult.rows?.[0] as Record<string, unknown>)?.total || '0'), 10);

    return c.json({
        success: true,
        data: {
            items: items.rows || [],
            pagination: { page, pageSize, total, pages: Math.ceil(total / pageSize) },
        },
    });
});

// ============================================================================
// GET /cases/:id — Full case detail
// ============================================================================

cases.get('/cases/:id', async (c) => {
    await ensureTablesOnce();
    const { id } = c.req.param();

    const [caseResult, observables, tasks, timeline] = await Promise.all([
        rawQuery(sql.raw(`SELECT * FROM cases WHERE id = '${esc(id)}'`)),
        rawQuery(sql.raw(`SELECT * FROM case_observables WHERE case_id = '${esc(id)}' ORDER BY created_at DESC`)),
        rawQuery(sql.raw(`SELECT * FROM case_tasks WHERE case_id = '${esc(id)}' ORDER BY created_at`)),
        rawQuery(sql.raw(`SELECT * FROM case_timeline WHERE case_id = '${esc(id)}' ORDER BY created_at DESC LIMIT 50`)),
    ]);

    const caseRow = caseResult.rows?.[0];
    if (!caseRow) throw new NotFoundError('Case', id);

    return c.json({
        success: true,
        data: {
            ...caseRow,
            observables: observables.rows || [],
            tasks: tasks.rows || [],
            timeline: timeline.rows || [],
            stats: {
                observableCount: (observables.rows || []).length,
                taskCount: (tasks.rows || []).length,
                tasksDone: (tasks.rows || []).filter((t: Record<string, unknown>) => t.status === 'done').length,
            },
        },
    });
});

// ============================================================================
// PUT /cases/:id — Update case
// ============================================================================

cases.put('/cases/:id', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const { id } = c.req.param();
    const body = UpdateCaseSchema.parse(await c.req.json().catch(() => ({})));

    const setClauses: string[] = ['updated_at = NOW()'];
    if (body.title) setClauses.push(`title = '${esc(body.title)}'`);
    if (body.description !== undefined) setClauses.push(`description = ${body.description ? `'${esc(body.description)}'` : 'NULL'}`);
    if (body.severity) setClauses.push(`severity = '${esc(body.severity)}'`);
    if (body.status) setClauses.push(`status = '${esc(body.status)}'`);
    if (body.assignee !== undefined) setClauses.push(`assignee = ${body.assignee ? `'${esc(body.assignee)}'` : 'NULL'}`);
    if (body.tlp) setClauses.push(`tlp = '${esc(body.tlp)}'`);
    if (body.tags) setClauses.push(`tags = ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]`);
    if (body.resolution) setClauses.push(`resolution = '${esc(body.resolution)}'`);

    const result = await rawQuery(sql.raw(`
        UPDATE cases SET ${setClauses.join(', ')} WHERE id = '${esc(id)}' RETURNING *
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('Case', id);
    return c.json({ success: true, data: row });
});

// ============================================================================
// DELETE /cases/:id — Archive/delete case
// ============================================================================

cases.delete('/cases/:id', requireRole('admin'), async (c) => {
    await ensureTablesOnce();
    const { id } = c.req.param();

    const result = await rawQuery(sql.raw(`DELETE FROM cases WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('Case', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// ============================================================================
// POST /cases/:id/observables — Attach observable
// ============================================================================

cases.post('/cases/:id/observables', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const { id } = c.req.param();
    const body = CaseObservableSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    // Verify case exists
    const caseCheck = await rawQuery(sql.raw(`SELECT id FROM cases WHERE id = '${esc(id)}'`));
    if (!caseCheck.rows?.[0]) throw new NotFoundError('Case', id);

    const result = await rawQuery(sql.raw(`
        INSERT INTO case_observables (case_id, entity_type, entity_id, notes, tags, added_by)
        VALUES ('${esc(id)}', '${esc(body.entityType)}', '${esc(body.entityId)}',
                ${body.notes ? `'${esc(body.notes)}'` : 'NULL'},
                ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}], '${esc(userId)}')
        ON CONFLICT (case_id, entity_type, entity_id) DO UPDATE SET
            notes = EXCLUDED.notes, tags = EXCLUDED.tags
        RETURNING *
    `));

    // Auto-add timeline entry
    await rawQuery(sql.raw(`
        INSERT INTO case_timeline (case_id, entry_type, content, created_by)
        VALUES ('${esc(id)}', 'action', 'Added ${esc(body.entityType)} observable: ${esc(body.entityId)}', '${esc(userId)}')
    `));

    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// ============================================================================
// POST /cases/:id/tasks — Add task
// ============================================================================

cases.post('/cases/:id/tasks', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const { id } = c.req.param();
    const body = CaseTaskSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    const caseCheck = await rawQuery(sql.raw(`SELECT id FROM cases WHERE id = '${esc(id)}'`));
    if (!caseCheck.rows?.[0]) throw new NotFoundError('Case', id);

    const result = await rawQuery(sql.raw(`
        INSERT INTO case_tasks (case_id, title, description, status, assignee, due_date, created_by)
        VALUES ('${esc(id)}', '${esc(body.title)}', ${body.description ? `'${esc(body.description)}'` : 'NULL'},
                '${esc(body.status)}', ${body.assignee ? `'${esc(body.assignee)}'` : 'NULL'},
                ${body.dueDate ? `'${esc(body.dueDate)}'` : 'NULL'}, '${esc(userId)}')
        RETURNING *
    `));

    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// ============================================================================
// PUT /cases/:id/tasks/:taskId — Update task
// ============================================================================

cases.put('/cases/:id/tasks/:taskId', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const { id, taskId } = c.req.param();
    const body = UpdateCaseTaskSchema.parse(await c.req.json().catch(() => ({})));

    const setClauses: string[] = ['updated_at = NOW()'];
    if (body.title) setClauses.push(`title = '${esc(body.title)}'`);
    if (body.description !== undefined) setClauses.push(`description = ${body.description ? `'${esc(body.description)}'` : 'NULL'}`);
    if (body.status) setClauses.push(`status = '${esc(body.status)}'`);
    if (body.assignee !== undefined) setClauses.push(`assignee = ${body.assignee ? `'${esc(body.assignee)}'` : 'NULL'}`);
    if (body.dueDate !== undefined) setClauses.push(`due_date = ${body.dueDate ? `'${esc(body.dueDate)}'` : 'NULL'}`);

    const result = await rawQuery(sql.raw(`
        UPDATE case_tasks SET ${setClauses.join(', ')}
        WHERE id = '${esc(taskId)}' AND case_id = '${esc(id)}'
        RETURNING *
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('Task', taskId);
    return c.json({ success: true, data: row });
});

// ============================================================================
// POST /cases/:id/timeline — Add timeline entry
// ============================================================================

cases.post('/cases/:id/timeline', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const { id } = c.req.param();
    const body = CaseTimelineSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    const caseCheck = await rawQuery(sql.raw(`SELECT id FROM cases WHERE id = '${esc(id)}'`));
    if (!caseCheck.rows?.[0]) throw new NotFoundError('Case', id);

    const result = await rawQuery(sql.raw(`
        INSERT INTO case_timeline (case_id, entry_type, content, created_by)
        VALUES ('${esc(id)}', '${esc(body.entryType)}', '${esc(body.content)}', '${esc(userId)}')
        RETURNING *
    `));

    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// ============================================================================
// POST /cases/from-alert/:alertId — Create case from escalated alert
// ============================================================================

cases.post('/cases/from-alert/:alertId', requireRole('admin', 'analyst'), async (c) => {
    await ensureTablesOnce();
    const { alertId } = c.req.param();
    const body = CaseFromAlertSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    // Find the alert
    const alert = alertStore.find(a => a.id === alertId);
    if (!alert) throw new NotFoundError('Alert', alertId);

    const title = body.title || `Case from Alert: ${alert.title}`;
    const description = `Auto-created from alert ${alertId}.\n\nOriginal alert: ${alert.message}\nSeverity: ${alert.severity}\nSource: ${alert.source || 'unknown'}`;
    const tags = [...body.tags, 'from-alert', `alert:${alertId}`];

    const caseResult = await rawQuery(sql.raw(`
        INSERT INTO cases (title, description, severity, status, assignee, tags, created_by)
        VALUES ('${esc(title)}', '${esc(description)}', '${esc(alert.severity)}', 'open',
                ${body.assignee ? `'${esc(body.assignee)}'` : 'NULL'},
                ARRAY[${tags.map(t => `'${esc(t)}'`).join(',')}], '${esc(userId)}')
        RETURNING *
    `));

    const createdCase = caseResult.rows?.[0] as Record<string, unknown>;

    // If alert has IOC metadata, auto-attach as observable
    if (alert.metadata?.iocId) {
        await rawQuery(sql.raw(`
            INSERT INTO case_observables (case_id, entity_type, entity_id, notes, added_by)
            VALUES ('${esc(String(createdCase.id))}', 'ioc', '${esc(String(alert.metadata.iocId))}',
                    'Auto-attached from alert', '${esc(userId)}')
            ON CONFLICT DO NOTHING
        `));
    }

    // Add initial timeline entry
    await rawQuery(sql.raw(`
        INSERT INTO case_timeline (case_id, entry_type, content, created_by)
        VALUES ('${esc(String(createdCase.id))}', 'action',
                'Case created from alert ${esc(alertId)} (${esc(alert.severity)} — ${esc(alert.title)})',
                '${esc(userId)}')
    `));

    // Mark alert as escalated
    alert.metadata = { ...alert.metadata, escalatedToCaseId: createdCase.id, escalatedAt: new Date().toISOString() };

    log.info('Case created from alert', { caseId: createdCase.id, alertId });
    return c.json({ success: true, data: createdCase }, 201);
});

export default cases;
