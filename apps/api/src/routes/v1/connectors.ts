/**
 * /v1/connectors — Feed manifest persistence (A2 of declarative engine).
 *
 * Routes:
 *   POST   /v1/connectors                  Create a new manifest version
 *   GET    /v1/connectors                  List manifests (filters: source, entity, activeOnly)
 *   GET    /v1/connectors/:id              Fetch a single manifest version
 *   POST   /v1/connectors/:id/activate     Make this version the active one for its source
 *   DELETE /v1/connectors/:id              Deactivate (rows are immutable; no hard delete)
 *
 * Audit trail lives in the table itself: every save is a new immutable row
 * carrying `created_by` (auth subject), `created_at`, and a per-source
 * monotonically increasing `version`. Activation transitions are visible
 * via `is_active` flips; the partial unique index enforces single-active.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import {
    createManifest,
    getById,
    listManifests,
    activate,
    deactivate,
    validateManifestBody,
    ConnectorConflictError,
} from '../../services/connectorStore';
import { draftMapper } from '../../services/draftMapper';
import { previewExtract, testManifest } from '../../services/connectorPreview';

const log = createLogger('Connectors');
const router = new Hono();

const WRITE_ROLES = ['admin', 'analyst', 'developer'] as const;

// All connector routes require authentication. Reads are open to authenticated
// users; writes require one of WRITE_ROLES.
router.use('*', requireAuth);

const CreateBody = z.object({
    source: z.string().min(1).max(100),
    entity: z.string().min(1).max(50),
    manifest: z.record(z.unknown()),
});

const ListQuery = z.object({
    source: z.string().optional(),
    entity: z.string().optional(),
    activeOnly: z.union([z.literal('true'), z.literal('false')]).optional(),
});

const PreviewBody = z.object({
    sample: z.string().min(1).max(256 * 1024),
    format: z.enum(['json', 'csv', 'text']),
    recordsPath: z.string().optional(),
    csv: z.object({
        delimiter: z.string().default(','),
        hasHeader: z.boolean().default(true),
    }).optional(),
    text: z.object({
        commentPrefix: z.string().default(''),
    }).optional(),
    limit: z.number().int().min(1).max(100).default(10),
});

const TestBody = z.object({
    sample: z.string().min(1).max(256 * 1024),
    manifest: z.record(z.unknown()),
    limit: z.number().int().min(1).max(100).default(10),
});

const SuggestBody = z.object({
    sample: z.string().min(1).max(256 * 1024), // 256 KB cap protects the LLM context
    format: z.enum(['json', 'csv', 'text']),
    entity: z.enum([
        'ioc', 'vulnerability', 'threat_actor', 'malware', 'campaign',
        'course_of_action', 'infrastructure', 'technique', 'tool',
    ]),
    sourceName: z.string().min(1).max(100),
    provider: z.enum(['gemini', 'openrouter', 'ollama']).optional(),
    recordsPathHint: z.string().optional(),
});

// POST /connectors — create a new manifest version
router.post('/connectors', requireRole(...WRITE_ROLES), async (c) => {
    const raw = await c.req.json().catch(() => ({}));
    const parsed = CreateBody.safeParse(raw);
    if (!parsed.success) {
        throw new ValidationError('Invalid request body', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }

    const { source, entity, manifest } = parsed.data;

    const validation = validateManifestBody(manifest);
    if (!validation.ok) {
        throw new ValidationError('manifest body failed engine schema validation', {
            issues: validation.errors,
        });
    }
    if ((manifest as Record<string, unknown>).entity !== entity) {
        throw new ValidationError(
            `manifest.entity '${(manifest as Record<string, unknown>).entity}' does not match request body entity '${entity}'`,
        );
    }

    const user = c.get('user');
    try {
        const row = await createManifest({
            source,
            entity,
            manifest: validation.data,
            createdBy: user.id,
        });
        log.info('Connector manifest created', { id: row.id, source, version: row.version, createdBy: user.id });
        return c.json({ success: true, data: row }, 201);
    } catch (err) {
        if (err instanceof ConnectorConflictError) {
            return c.json({ success: false, error: err.message }, 409);
        }
        throw err;
    }
});

// GET /connectors — list manifests with optional filters
router.get('/connectors', async (c) => {
    const parsed = ListQuery.safeParse({
        source: c.req.query('source'),
        entity: c.req.query('entity'),
        activeOnly: c.req.query('activeOnly'),
    });
    if (!parsed.success) {
        throw new ValidationError('Invalid query parameters', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }
    const { source, entity, activeOnly } = parsed.data;

    const rows = await listManifests({
        source,
        entity,
        activeOnly: activeOnly === 'true',
    });
    return c.json({ success: true, data: rows, count: rows.length });
});

// GET /connectors/:id — fetch a single manifest version
router.get('/connectors/:id', async (c) => {
    const { id } = c.req.param();
    const row = await getById(id);
    if (!row) throw new NotFoundError('Connector', id);
    return c.json({ success: true, data: row });
});

// POST /connectors/:id/activate — flip the active version for this source
router.post('/connectors/:id/activate', requireRole(...WRITE_ROLES), async (c) => {
    const { id } = c.req.param();
    const row = await activate(id);
    if (!row) throw new NotFoundError('Connector', id);
    const user = c.get('user');
    log.info('Connector manifest activated', { id, source: row.source, version: row.version, by: user.id });
    return c.json({ success: true, data: row });
});

// POST /connectors/suggest — LLM draft-mapper (A5)
// Takes a sample payload + entity + sourceName, returns either a runnable
// manifest (`status: 'ok'`) or an explicit `status: 'couldnt_map'` with a
// reason. Never returns a stub manifest pretending to be real — falls back
// to an empty skeleton (mapping: {}, enabled: false) when the LLM is
// unreachable or its output fails validation/dry-run.
router.post('/connectors/suggest', requireRole(...WRITE_ROLES), async (c) => {
    const raw = await c.req.json().catch(() => ({}));
    const parsed = SuggestBody.safeParse(raw);
    if (!parsed.success) {
        throw new ValidationError('Invalid request body', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }

    const result = await draftMapper(parsed.data);
    log.info('Connector suggest', {
        sourceName: parsed.data.sourceName,
        entity: parsed.data.entity,
        status: result.status,
        dryRun: result.dryRun,
    });
    return c.json({ success: true, data: result });
});

// POST /connectors/preview — extract raw records from a sample (A6 backend)
// Used by the connector builder UI for field discovery: paste a sample, see
// what shape the engine extracts, then map fields against the result. No
// manifest needed — only extract config (recordsPath / csv options).
router.post('/connectors/preview', requireRole(...WRITE_ROLES), async (c) => {
    const raw = await c.req.json().catch(() => ({}));
    const parsed = PreviewBody.safeParse(raw);
    if (!parsed.success) {
        throw new ValidationError('Invalid request body', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }
    return c.json({ success: true, data: previewExtract(parsed.data) });
});

// POST /connectors/test — dry-run a full manifest against a sample (A6 backend)
// The UI calls this after the operator has assembled (manually or via /suggest)
// a manifest, to see exactly what records the engine extracts. Returns the
// dry-run stats + the first N canonical records.
router.post('/connectors/test', requireRole(...WRITE_ROLES), async (c) => {
    const raw = await c.req.json().catch(() => ({}));
    const parsed = TestBody.safeParse(raw);
    if (!parsed.success) {
        throw new ValidationError('Invalid request body', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }
    return c.json({ success: true, data: testManifest(parsed.data) });
});

// DELETE /connectors/:id — soft delete (deactivate)
router.delete('/connectors/:id', requireRole(...WRITE_ROLES), async (c) => {
    const { id } = c.req.param();
    const row = await deactivate(id);
    if (!row) throw new NotFoundError('Connector', id);
    const user = c.get('user');
    log.info('Connector manifest deactivated', { id, by: user.id });
    return c.json({ success: true, data: { id, isActive: false } });
});

export default router;
