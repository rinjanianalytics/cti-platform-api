/**
 * Vulnerabilities Routes (CISA KEV + CVE)
 *
 * Extracted from v1.ts — list and detail endpoints for vulnerabilities.
 */

import { Hono } from 'hono';
import { db, eq, sql, rawQuery } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import * as opensearch from '../../services/opensearch';
import { createLogger } from '../../lib/logger';
import { NotFoundError } from '../../lib/errors';
import { VulnFilterSchema } from '../../lib/schemas';
import { paginate } from './helpers';
import { toVulnDTO } from '../../dto';
import { parseCursorParams, buildCursorResponse } from '../../lib/pagination';
import { escSql } from '../../lib/sanitize';

const log = createLogger('v1:vulnerabilities');
const router = new Hono();

// ============================================================================
// Vulnerabilities (CISA KEV + CVE)
// ============================================================================

router.get('/vulnerabilities', async (c) => {
    const { page, pageSize, q, severity, sortBy, exploited, vendor, dateFrom, dateTo, ransomware } = VulnFilterSchema.parse(c.req.query());

    // Use OpenSearch for fast search with facets
    const result = await opensearch.unifiedSearch({
        query: q || '',
        filters: {
            entityType: ['vulnerability'],
            ...(severity ? { severity: [severity] } : {}),
            ...(dateFrom ? { dateFrom } : {}),
            ...(dateTo ? { dateTo } : {}),
        },
        sort: { field: sortBy, order: 'desc' },
        pagination: { page, limit: pageSize },
        aggregations: true,
    });

    // OpenSearch stores cve under `value`; remap to `cveId` so the DTO
    // can pick the canonical field, then coerce the row's types
    // (cvssScore string→number, dates→ISO) in one place.
    const mappedItems = result.items.map((item: Record<string, unknown>) =>
        toVulnDTO({
            ...item,
            cveId: item.cveId ?? item.value,
            publishedDate: item.publishedDate ?? item.createdAt ?? item.updatedAt,
        }),
    );

    return c.json({
        success: true,
        data: {
            items: mappedItems,
            filters: { severity, exploited, vendor, dateFrom, dateTo, ransomware, q },
            pagination: paginate(page, pageSize, result.total),
            facets: result.facets,
            took: result.took,
        },
    });
});

// ============================================================================
// Vulnerabilities — Cursor Pagination (PostgreSQL direct)
// ============================================================================

router.get('/vulnerabilities/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    let whereClause = '';
    if (cursor) {
        const op = direction === 'next' ? '<' : '>';
        whereClause = `WHERE (updated_at, id::text) ${op} ('${escSql(cursor.timestamp)}', '${escSql(cursor.id)}')`;
    }

    const orderDir = direction === 'next' ? 'DESC' : 'ASC';

    const result = await rawQuery(
        `SELECT id, cve_id, description, severity, cvss_score, vendor_project, product,
                is_exploited, published_date, created_at, updated_at
         FROM vulnerabilities ${whereClause}
         ORDER BY updated_at ${orderDir} NULLS LAST, id ${orderDir}
         LIMIT ${limit + 1}`
    );

    const rows = (result.rows || []).map((row: Record<string, unknown>) => toVulnDTO(row));

    if (direction === 'prev') rows.reverse();

    const response = buildCursorResponse(rows, limit, (row) => ({
        timestamp: String(row.updatedAt ?? row.createdAt ?? ''),
        id: String(row.id ?? ''),
    }));

    return c.json({ success: true, ...response });
});


router.get('/vulnerabilities/:cveId', async (c) => {
    const { cveId } = c.req.param();

    // Only uppercase CVE IDs (e.g. CVE-2018-0175), leave UUIDs as-is
    const lookupId = cveId.startsWith('CVE-') || cveId.startsWith('cve-') ? cveId.toUpperCase() : cveId;

    // Use OpenSearch getById for lookup by CVE ID or UUID
    const result = await opensearch.getById(lookupId, 'vulnerability');

    if (!result.item) {
        throw new NotFoundError('CVE', cveId);
    }

    const item = result.item;

    // Fetch additional fields from PostgreSQL if missing in OpenSearch
    let vendorProject = item.vendorProject || '';
    let product = item.product || '';

    if (!vendorProject || !product) {
        try {
            const pgResult = await db
                .select({
                    vendorProject: vulnerabilities.vendorProject,
                    product: vulnerabilities.product,
                })
                .from(vulnerabilities)
                .where(eq(vulnerabilities.cveId, String(item.value || lookupId).toUpperCase()))
                .limit(1);

            if (pgResult.length > 0) {
                vendorProject = vendorProject || pgResult[0].vendorProject || '';
                product = product || pgResult[0].product || '';
            }
        } catch (pgErr) {
            log.warn('PostgreSQL fallback failed for CVE detail', { cveId, error: (pgErr as Error)?.message });
        }
    }

    // DTO owns the canonical shape; the route adds the PG-recovered
    // vendor/product and preserves the raw OpenSearch document for the
    // detail page's diagnostic panel.
    const mappedData = {
        ...toVulnDTO({
            ...item,
            cveId: item.cveId ?? item.value,
            publishedDate: item.publishedDate ?? item.createdAt ?? item.updatedAt,
            vendorProject,
            product,
        }),
        rawData: (item.rawData ?? null) as Record<string, unknown> | null,
    };

    return c.json({ success: true, data: mappedData, took: result.took });
});

// ============================================================================
// Vulnerability Write Operations (Phase AG — CRUD Completeness)
// ============================================================================

import { requireAuth, requireRole } from '../../middleware/auth';
import { UpdateVulnerabilitySchema, VulnLinkIOCSchema } from '../../lib/schemas';

/** PUT /v1/vulnerabilities/:id — Update vulnerability metadata */
router.put('/vulnerabilities/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = UpdateVulnerabilitySchema.parse(await c.req.json().catch(() => ({})));

    const setClauses: string[] = ['updated_at = NOW()'];
    const esc = (s: string) => s.replace(/'/g, "''");

    if (body.severity) setClauses.push(`severity = '${esc(body.severity)}'`);
    if (body.notes) setClauses.push(`raw_data = COALESCE(raw_data, '{}'::jsonb) || '${JSON.stringify({ notes: body.notes }).replace(/'/g, "''")}'::jsonb`);
    if (body.tags) setClauses.push(`tags = ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]`);
    if (body.exploited !== undefined) setClauses.push(`is_exploited = ${body.exploited}`);

    // Support both UUID and CVE ID lookups
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    const whereCol = isUUID ? 'id' : 'cve_id';
    const whereVal = isUUID ? id : id.toUpperCase();

    const result = await rawQuery(sql.raw(`
        UPDATE vulnerabilities SET ${setClauses.join(', ')}
        WHERE ${whereCol} = '${esc(whereVal)}'
        RETURNING id, cve_id, severity, is_exploited, updated_at
    `));

    const row = result.rows?.[0];
    if (!row) throw new NotFoundError('Vulnerability', id);
    return c.json({ success: true, data: row });
});

/** POST /v1/vulnerabilities/:id/link — Link IOC to vulnerability */
router.post('/vulnerabilities/:id/link', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = VulnLinkIOCSchema.parse(await c.req.json().catch(() => ({})));
    const esc = (s: string) => s.replace(/'/g, "''");

    // Verify the vulnerability exists
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    const whereCol = isUUID ? 'id' : 'cve_id';
    const whereVal = isUUID ? id : id.toUpperCase();

    const vulnCheck = await rawQuery(sql.raw(`SELECT id, cve_id FROM vulnerabilities WHERE ${whereCol} = '${esc(whereVal)}' LIMIT 1`));
    if (!vulnCheck.rows?.[0]) throw new NotFoundError('Vulnerability', id);

    // Create the link in a vuln_ioc_links table (auto-create)
    await rawQuery(sql.raw(`
        CREATE TABLE IF NOT EXISTS vuln_ioc_links (
            id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            vulnerability_id TEXT NOT NULL,
            ioc_id TEXT NOT NULL,
            relationship TEXT NOT NULL DEFAULT 'related-to',
            notes TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(vulnerability_id, ioc_id)
        )
    `));

    const vulnId = (vulnCheck.rows[0] as Record<string, unknown>).id as string;
    await rawQuery(sql.raw(`
        INSERT INTO vuln_ioc_links (vulnerability_id, ioc_id, relationship, notes)
        VALUES ('${esc(vulnId)}', '${esc(body.iocId)}', '${esc(body.relationship)}', ${body.notes ? `'${esc(body.notes)}'` : 'NULL'})
        ON CONFLICT (vulnerability_id, ioc_id) DO UPDATE SET
            relationship = EXCLUDED.relationship,
            notes = EXCLUDED.notes
    `));

    log.info('Vulnerability-IOC link created', { vulnId, iocId: body.iocId, relationship: body.relationship });
    return c.json({
        success: true,
        data: {
            vulnerabilityId: vulnId,
            iocId: body.iocId,
            relationship: body.relationship,
        },
    }, 201);
});

// ============================================================================
// CVSS Enrichment from NVD
// ============================================================================

import { enrichVulnerability, fetchCvss } from '../../services/vulnerabilityEnrichment';

/**
 * POST /v1/vulnerabilities/:cveId/enrich — fetch CVSS from NVD for one CVE.
 * Skips if the row already has a score. Admin/analyst only.
 */
router.post('/vulnerabilities/:cveId/enrich', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { cveId } = c.req.param();
    const result = await enrichVulnerability(cveId);
    if (!result) {
        // Distinguish "already has a score" from "NVD has no data".
        const [row] = await db.select({ cvssScore: vulnerabilities.cvssScore })
            .from(vulnerabilities).where(eq(vulnerabilities.cveId, cveId.toUpperCase())).limit(1);
        if (!row) throw new NotFoundError('Vulnerability', cveId);
        return c.json({
            success: true,
            data: {
                cveId,
                applied: false,
                reason: row.cvssScore != null ? 'already-scored' : 'no-nvd-data',
            },
        });
    }
    return c.json({
        success: true,
        data: { cveId, applied: true, ...result },
    });
});

/**
 * POST /v1/vulnerabilities/enrich/bulk — back-fill CVSS for all CVEs with
 * NULL cvssScore. Heavy operation; NVD allows ~5 req/30s without API key,
 * 50/30s with one. Capped at 100 per call.
 */
router.post('/vulnerabilities/enrich/bulk', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json<{ limit?: number }>().catch(() => ({} as { limit?: number }));
    const limit = Math.min(Math.max(body.limit ?? 30, 1), 100);

    const candidates = await db.select({ cveId: vulnerabilities.cveId })
        .from(vulnerabilities)
        // No drizzle helper for IS NULL on numeric — use raw SQL fragment.
        .where(sql`${vulnerabilities.cvssScore} IS NULL`)
        .limit(limit);

    let enriched = 0;
    let notFound = 0;
    const errors: Array<{ cveId: string; error: string }> = [];

    for (const row of candidates) {
        let sourceUsed: 'osv' | 'nvd' | null = null;
        try {
            const r = await fetchCvss(row.cveId);
            if (!r) { notFound++; continue; }
            sourceUsed = r.source;
            await db.update(vulnerabilities)
                .set({
                    cvssScore: r.score.toString(),
                    cvssVector: r.vector,
                    severity: r.severity,
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.cveId, row.cveId));
            enriched++;
        } catch (err) {
            errors.push({ cveId: row.cveId, error: (err as Error).message });
        }
        // Only throttle when NVD was the source — OSV has no rate limit
        // so an OSV-served batch can rip through in seconds. If `null`
        // (both sources failed), assume NVD was tried and throttle.
        if (sourceUsed !== 'osv') {
            await new Promise(r => setTimeout(r, NVD_API_KEY_PRESENT ? 200 : 6500));
        }
    }

    return c.json({
        success: true,
        data: { considered: candidates.length, enriched, notFound, errors },
    });
});

const NVD_API_KEY_PRESENT = !!(process.env.CVE_API_KEY || process.env.NVD_API_KEY);

export default router;
