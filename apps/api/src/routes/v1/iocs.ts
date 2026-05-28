/**
 * IOC Routes (Indicators of Compromise)
 *
 * Extracted from v1.ts — list and detail endpoints for IOCs.
 * Supports both offset pagination (/iocs) and cursor pagination (/iocs/cursor).
 */

import { Hono } from 'hono';
import * as opensearch from '../../services/opensearch';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { IOCFilterSchema } from '../../lib/schemas';
import { paginate } from './helpers';
import { parseCursorParams, buildCursorResponse, IdParamSchema } from '../../lib/pagination';
import { db, eq, sql } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { requireAuth, requireRole } from '../../middleware/auth';
import {
    IOCCreateSchema, IOCUpdateSchema, IOCRevokeSchema, IOCExpireSchema, IOCVerdictSchema,
} from '../../lib/schemas';
import { ConflictError } from '../../lib/errors';

const router = new Hono();

/**
 * The IOC pipeline stores all hashes under a single canonical type `hash` —
 * the granular algorithm (md5/sha1/sha256) lives in `patternType` or the
 * value itself. Front-end dropdowns expose the granular variants for UX, so
 * we normalise back to the canonical bucket before querying.
 */
function normaliseIocType(raw: string): string {
    const norm = raw.toLowerCase().trim();
    if (norm.startsWith('hash')) return 'hash';
    if (norm === 'ipv4' || norm === 'ipv6') return 'ip';
    return norm;
}

// ============================================================================
// IOCs (Indicators of Compromise) — Offset Pagination (OpenSearch)
// ============================================================================

router.get('/iocs', async (c) => {
    const { page, pageSize, q, type, source, severity, dateFrom, dateTo } = IOCFilterSchema.parse(c.req.query());

    // Use OpenSearch for fast search with facets.
    // NOTE: `type` filter maps to the OpenSearch `type` field (ip/domain/url/hash/email/cve).
    // The granular dropdown options like `hash-sha256` should be normalised to
    // the canonical bucket before reaching here.
    const result = await opensearch.unifiedSearch({
        query: q || '',
        filters: {
            entityType: ['ioc'],
            ...(type ? { type: [normaliseIocType(type)] } : {}),
            ...(source ? { source: [source] } : {}),
            ...(severity ? { severity: [severity] } : {}),
            ...(dateFrom ? { dateFrom } : {}),
            ...(dateTo ? { dateTo } : {}),
        },
        sort: { field: 'updatedAt', order: 'desc' },
        pagination: { page, limit: pageSize },
        aggregations: true,
    });

    // Map OpenSearch fields to frontend-expected names for IOCs
    const mappedItems = result.items.map((item: Record<string, unknown>) => ({
        ...item,
        threatType: item.description !== 'unknown' ? item.description : null,
        firstSeen: item.createdAt,
        lastSeen: item.updatedAt,
    }));

    return c.json({
        success: true,
        data: {
            items: mappedItems,
            filters: { type, source, severity, q },
            pagination: paginate(page, pageSize, result.total),
            facets: result.facets,
            took: result.took,
        },
    });
});

// ============================================================================
// IOCs — Cursor Pagination (PostgreSQL direct, O(1) seek)
// ============================================================================

router.get('/iocs/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    // The cursor token is decoded from a base64 query param, so its fields are
    // attacker-controllable. Every dynamic value goes through `sql` parameter
    // binding; only the static direction-dependent SQL fragments are inlined.
    const isNext = direction === 'next';
    const result = await db.execute(
        cursor
            ? (isNext
                ? sql`SELECT id, type, value, source, threat_type, confidence, severity,
                             risk_score, first_seen, last_seen, tags, created_at, updated_at
                      FROM iocs
                      WHERE (updated_at, id::text) < (${cursor.timestamp}::timestamptz, ${cursor.id})
                      ORDER BY updated_at DESC, id DESC
                      LIMIT ${limit + 1}`
                : sql`SELECT id, type, value, source, threat_type, confidence, severity,
                             risk_score, first_seen, last_seen, tags, created_at, updated_at
                      FROM iocs
                      WHERE (updated_at, id::text) > (${cursor.timestamp}::timestamptz, ${cursor.id})
                      ORDER BY updated_at ASC, id ASC
                      LIMIT ${limit + 1}`)
            : (isNext
                ? sql`SELECT id, type, value, source, threat_type, confidence, severity,
                             risk_score, first_seen, last_seen, tags, created_at, updated_at
                      FROM iocs
                      ORDER BY updated_at DESC, id DESC
                      LIMIT ${limit + 1}`
                : sql`SELECT id, type, value, source, threat_type, confidence, severity,
                             risk_score, first_seen, last_seen, tags, created_at, updated_at
                      FROM iocs
                      ORDER BY updated_at ASC, id ASC
                      LIMIT ${limit + 1}`)
    );

    const resultRows: Record<string, unknown>[] = Array.isArray(result)
        ? (result as Record<string, unknown>[])
        : (((result as { rows?: Record<string, unknown>[] }).rows) ?? []);

    const rows = resultRows.map((row) => ({
        ...row,
        threatType: row.threat_type,
        firstSeen: row.first_seen,
        lastSeen: row.last_seen,
        riskScore: row.risk_score,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    }));

    // Reverse order for 'prev' direction queries
    if (!isNext) rows.reverse();

    const response = buildCursorResponse(rows, limit, (row: Record<string, unknown>) => ({
        timestamp: String(row.updated_at || row.created_at || ''),
        id: String(row.id || ''),
    }));

    return c.json({ success: true, ...response });
});

// ============================================================================
// Get IOC by ID (UUID) or value
// ============================================================================

router.get('/iocs/:idOrValue', async (c) => {
    const { idOrValue } = c.req.param();

    // Try OpenSearch first (fast, indexed)
    const result = await opensearch.getById(idOrValue, 'ioc');

    if (result.item) {
        const item = result.item;
        const mappedData = {
            ...item,
            threatType: item.description !== 'unknown' ? item.description : null,
            firstSeen: item.createdAt,
            lastSeen: item.updatedAt,
        };
        return c.json({ success: true, data: mappedData, took: result.took });
    }

    // Fallback: query PostgreSQL directly (handles IOCs not yet indexed in OpenSearch)
    // The original `SELECT *` is preserved so any columns added via migration but
    // not yet reflected in the Drizzle schema (e.g. `description`, `risk_score`)
    // continue to flow through to the client. Inputs are parameter-bound.
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(idOrValue);
    const pgResult = await db.execute(
        isUUID
            ? sql`SELECT * FROM iocs WHERE id = ${idOrValue}::uuid LIMIT 1`
            : sql`SELECT * FROM iocs WHERE value = ${idOrValue} LIMIT 1`
    );

    const rows: Record<string, unknown>[] = Array.isArray(pgResult)
        ? (pgResult as Record<string, unknown>[])
        : (((pgResult as { rows?: Record<string, unknown>[] }).rows) ?? []);
    const row = rows[0];
    if (!row) {
        throw new NotFoundError('IOC', idOrValue);
    }

    const mappedData = {
        id: row.id,
        type: row.type,
        value: row.value,
        source: row.source,
        severity: row.severity,
        confidence: row.confidence,
        tags: row.tags,
        description: row.description ?? row.threat_type,
        threatType: row.threat_type,
        riskScore: row.risk_score,
        firstSeen: row.first_seen,
        lastSeen: row.last_seen,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        entityType: 'ioc',
    };

    return c.json({ success: true, data: mappedData, source: 'database' });
});

// ============================================================================
// IOC Lifecycle Management (MISP / STIX 2.1 inspired)
// ============================================================================

const RETURNING_COLUMNS = {
    id: iocs.id,
    type: iocs.type,
    value: iocs.value,
    severity: iocs.severity,
    confidence: iocs.confidence,
    tags: iocs.tags,
    threatType: iocs.threatType,
    updatedAt: iocs.updatedAt,
} as const;

/**
 * Validate `:id` path param as a UUID, or throw 400.
 *
 * Accepts `string | undefined` because hono ≥4.12 widened `c.req.param()`
 * to possibly-undefined. A missing id zod-fails here and surfaces as a
 * clean 400 rather than a downstream crash.
 */
function parseIocId(raw: string | undefined): string {
    const parsed = IdParamSchema.shape.id.safeParse(raw);
    if (!parsed.success) throw new ValidationError('Invalid IOC id (must be UUID)');
    return parsed.data;
}

/**
 * Build a JSONB merge fragment that ANDs onto the existing raw_data column.
 *
 * Pass the object directly so the driver serialises it once into a JSONB
 * object. Passing JSON.stringify(patch) caused a double-encode under
 * postgres-js: the cast produced a JSONB *string scalar* and `||` turned the
 * result into [{}, "<stringified>"] instead of a merged object.
 */
function mergeRawData(patch: Record<string, unknown>) {
    return sql`COALESCE(${iocs.rawData}, '{}'::jsonb) || ${patch}::jsonb`;
}

/** POST /v1/iocs — Create a single IOC manually.
 *
 *  Distinct from `POST /bulk/iocs` (bulk ingest). Returns 409 on duplicate
 *  `value`. Analysts can create; admins can too.
 */
router.post('/iocs', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = IOCCreateSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    const now = new Date();
    const rawData = body.notes
        ? { notes: body.notes, createdBy: userId }
        : { createdBy: userId };

    try {
        const [row] = await db.insert(iocs).values({
            type: body.type,
            value: body.value,
            source: body.source,
            severity: body.severity ?? null,
            confidence: body.confidence ?? null,
            tags: body.tags ?? null,
            threatType: body.threatType ?? null,
            firstSeen: now,
            lastSeen: now,
            rawData,
        }).returning({
            id: iocs.id,
            type: iocs.type,
            value: iocs.value,
            source: iocs.source,
            severity: iocs.severity,
            confidence: iocs.confidence,
            tags: iocs.tags,
            threatType: iocs.threatType,
            firstSeen: iocs.firstSeen,
            lastSeen: iocs.lastSeen,
            createdAt: iocs.createdAt,
        });

        return c.json({ success: true, data: row }, 201);
    } catch (err) {
        // Drizzle / postgres-js surfaces unique-violation as code 23505.
        const e = err as { code?: string; message?: string };
        if (e.code === '23505' || (e.message ?? '').includes('duplicate key')) {
            throw new ConflictError(`IOC with value "${body.value}" already exists`);
        }
        throw err;
    }
});

/** PUT /v1/iocs/:id — Partial update of IOC fields */
router.put('/iocs/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = parseIocId(c.req.param('id'));
    const body = IOCUpdateSchema.parse(await c.req.json().catch(() => ({})));

    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (body.severity) updates.severity = body.severity;
    if (body.confidence !== undefined) updates.confidence = body.confidence;
    if (body.tags) updates.tags = body.tags;
    if (body.threatType) updates.threatType = body.threatType;
    if (body.notes) updates.rawData = mergeRawData({ notes: body.notes });

    const [row] = await db.update(iocs)
        .set(updates)
        .where(eq(iocs.id, id))
        .returning(RETURNING_COLUMNS);

    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: row });
});

/** POST /v1/iocs/:id/revoke — Mark IOC as revoked (soft-delete with reason) */
router.post('/iocs/:id/revoke', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = parseIocId(c.req.param('id'));
    const body = IOCRevokeSchema.parse(await c.req.json().catch(() => ({})));

    const [row] = await db.update(iocs)
        .set({
            rawData: mergeRawData({
                revoked: true,
                revokeReason: body.reason,
                revokedAt: new Date().toISOString(),
            }),
            updatedAt: new Date(),
        })
        .where(eq(iocs.id, id))
        .returning({ id: iocs.id, type: iocs.type, value: iocs.value });

    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: { ...row, revoked: true, reason: body.reason } });
});

/** POST /v1/iocs/:id/expire — Set valid_until date for automatic expiry */
router.post('/iocs/:id/expire', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = parseIocId(c.req.param('id'));
    const body = IOCExpireSchema.parse(await c.req.json().catch(() => ({})));

    const [row] = await db.update(iocs)
        .set({
            rawData: mergeRawData({ validUntil: body.validUntil }),
            updatedAt: new Date(),
        })
        .where(eq(iocs.id, id))
        .returning({ id: iocs.id, type: iocs.type, value: iocs.value });

    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: { ...row, validUntil: body.validUntil } });
});

/** POST /v1/iocs/:id/verdict — Assign analyst verdict */
router.post('/iocs/:id/verdict', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = parseIocId(c.req.param('id'));
    const body = IOCVerdictSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';

    const [row] = await db.update(iocs)
        .set({
            rawData: mergeRawData({
                verdict: body.verdict,
                verdictNotes: body.notes,
                verdictBy: userId,
                verdictAt: new Date().toISOString(),
            }),
            updatedAt: new Date(),
        })
        .where(eq(iocs.id, id))
        .returning({ id: iocs.id, type: iocs.type, value: iocs.value });

    if (!row) throw new NotFoundError('IOC', id);
    return c.json({ success: true, data: { ...row, verdict: body.verdict } });
});

export default router;
