/**
 * TAXII 2.1 Server — Hono Routes
 *
 * Implements the TAXII 2.1 protocol (OASIS standard) for bidirectional
 * threat intelligence sharing. Enables external platforms (MISP, OpenCTI,
 * TheHive, CERTs) to subscribe to Rinjani's intelligence feeds.
 *
 * Endpoints:
 *   GET  /taxii2/              → Discovery resource
 *   GET  /taxii2/collections/  → List available collections
 *   GET  /taxii2/collections/:id/objects/ → Get STIX objects
 *   POST /taxii2/collections/:id/objects/ → Add STIX objects (inbound ingestion)
 *   GET  /taxii2/collections/:id/manifest/ → Object manifests
 *
 * Spec: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html
 */

import { Hono } from 'hono';
import type { Context, Next } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { db, sql, rawQuery } from '@rinjani/db';
import { createLogger } from '../lib/logger';
import { escSql } from '../lib/sanitize';
import { TaxiiInboundSchema, TaxiiEnvelopeQuerySchema } from '../lib/schemas';

const log = createLogger('TAXII');

const taxiiRouter = new Hono();

// ============================================================================
// TAXII API-Key Authentication Middleware
// ============================================================================

/**
 * Bearer-token auth for TAXII data endpoints.
 * Validates against config_api_keys table or TAXII_API_KEY env var.
 * Discovery and collection listing remain public.
 */
async function taxiiAuth(c: Context, next: Next) {
    const authHeader = c.req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return taxiiResponse(c, {
            title: 'Unauthorized',
            description: 'TAXII data endpoints require a Bearer token in the Authorization header',
            error_code: 'UNAUTHORIZED',
        }, 401);
    }

    const token = authHeader.slice(7).trim();

    // Check environment variable shortcut first
    const envKey = process.env.TAXII_API_KEY;
    if (envKey && token === envKey) {
        await next();
        return;
    }

    // Check database config_api_keys table
    try {
        const result = await rawQuery<{ id: string }>(
            `SELECT id FROM config_api_keys WHERE key_value = '${escSql(token)}' AND is_active = true LIMIT 1`
        );

        if (result.rows && result.rows.length > 0) {
            await next();
            return;
        }
    } catch (err) {
        log.warn('TAXII auth DB check failed, falling back to env-only', { error: (err as Error).message });
        // If DB check fails but env key was set and didn't match, reject
    }

    return taxiiResponse(c, {
        title: 'Unauthorized',
        description: 'Invalid or expired API key',
        error_code: 'INVALID_API_KEY',
    }, 401);
}

// TLP marking definition for inclusion in bundles
const TLP_WHITE_MARKING = {
    type: 'marking-definition' as const,
    spec_version: '2.1',
    id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    created: '2017-01-20T00:00:00.000Z',
    definition_type: 'tlp',
    name: 'TLP:WHITE',
    definition: { tlp: 'white' },
};

// ============================================================================
// TAXII Content-Type
// ============================================================================

const TAXII_CONTENT_TYPE = 'application/taxii+json;version=2.1';

function taxiiResponse(c: Context, data: object, status = 200) {
    return c.json(data, status as ContentfulStatusCode, {
        'Content-Type': TAXII_CONTENT_TYPE,
    });
}

// ============================================================================
// Collections Definition
// ============================================================================

interface TaxiiCollection {
    id: string;
    title: string;
    description: string;
    can_read: boolean;
    can_write: boolean;
    media_types: string[];
}

const COLLECTIONS: TaxiiCollection[] = [
    {
        id: 'rinjani-iocs',
        title: 'Rinjani IOC Feed',
        description: 'Indicators of Compromise from all integrated CTI sources',
        can_read: true,
        can_write: false,
        media_types: ['application/stix+json;version=2.1'],
    },
    {
        id: 'rinjani-vulnerabilities',
        title: 'Rinjani Vulnerability Feed',
        description: 'CVE and CISA KEV vulnerability data in STIX 2.1 format',
        can_read: true,
        can_write: false,
        media_types: ['application/stix+json;version=2.1'],
    },
    {
        id: 'rinjani-threat-actors',
        title: 'Rinjani Threat Actor Feed',
        description: 'Threat actor profiles aligned with MITRE ATT&CK',
        can_read: true,
        can_write: false,
        media_types: ['application/stix+json;version=2.1'],
    },
    {
        id: 'rinjani-inbound',
        title: 'Rinjani Inbound Intelligence',
        description: 'Submit external STIX bundles for ingestion',
        can_read: false,
        can_write: true,
        media_types: ['application/stix+json;version=2.1'],
    },
];

// ============================================================================
// STIX Type Mapping (reused from stixPipeline)
// ============================================================================

const STIX_TYPE_MAP: Record<string, string> = {
    ip: 'ipv4-addr', domain: 'domain-name', url: 'url',
    hash: 'file', email: 'email-addr',
};

const PLATFORM_IDENTITY = {
    type: 'identity' as const,
    id: 'identity--rinjani-analytics',
    spec_version: '2.1',
    created: '2024-01-01T00:00:00.000Z',
    modified: new Date().toISOString(),
    name: 'Rinjani Analytics CTI Platform',
    identity_class: 'system',
};


// ============================================================================
// Discovery
// ============================================================================

taxiiRouter.get('/', (c) => {
    return taxiiResponse(c, {
        title: 'RinjaniAnalytics TAXII Server',
        description: 'TAXII 2.1 server for the Rinjani CTI Platform',
        contact: 'support@rinjanianalytics.io',
        default: '/taxii2/collections/',
        api_roots: ['/taxii2/'],
    });
});

// ============================================================================
// Collections
// ============================================================================

taxiiRouter.get('/collections/', (c) => {
    return taxiiResponse(c, {
        collections: COLLECTIONS,
    });
});

taxiiRouter.get('/collections/:id', (c) => {
    const id = c.req.param('id')!; // route-guaranteed by :id pattern
    const collection = COLLECTIONS.find(col => col.id === id);

    if (!collection) {
        return taxiiResponse(c, {
            title: 'Not Found',
            description: `Collection "${id}" not found`,
            error_code: 'COLLECTION_NOT_FOUND',
        }, 404);
    }

    return taxiiResponse(c, collection);
});

// ============================================================================
// Get Objects (STIX 2.1 Bundle) — LIVE DATA
// ============================================================================

taxiiRouter.get('/collections/:id/objects/', taxiiAuth, async (c) => {
    const id = c.req.param('id')!; // route-guaranteed by :id pattern
    const collection = COLLECTIONS.find(col => col.id === id);

    if (!collection || !collection.can_read) {
        return taxiiResponse(c, {
            title: 'Not Found',
            description: `Collection "${id}" not found or not readable`,
        }, 404);
    }

    // Parse TAXII query params
    const { added_after: addedAfter, limit, next, 'match[type]': matchType, 'match[id]': matchId } = TaxiiEnvelopeQuerySchema.parse(c.req.query());

    log.info('TAXII objects requested', { collection: id, addedAfter, limit, matchType });

    try {
        const objects: Record<string, unknown>[] = [PLATFORM_IDENTITY, TLP_WHITE_MARKING];
        let more = false;

        if (id === 'rinjani-iocs') {
            const result = await queryIOCsAsSTIX(addedAfter, limit, next, matchId);
            objects.push(...result.objects);
            more = result.more;
        } else if (id === 'rinjani-vulnerabilities') {
            const result = await queryVulnsAsSTIX(addedAfter, limit, next, matchId);
            objects.push(...result.objects);
            more = result.more;
        } else if (id === 'rinjani-threat-actors') {
            const result = await queryActorsAsSTIX(addedAfter, limit, next, matchId);
            objects.push(...result.objects);
            more = result.more;
        }

        // Apply match[type] filter if specified
        const filtered = matchType
            ? objects.filter(o => o.type === matchType)
            : objects;

        const bundle = {
            type: 'bundle',
            id: `bundle--${crypto.randomUUID()}`,
            objects: filtered,
        };

        return taxiiResponse(c, {
            ...bundle,
            more,
        });
    } catch (error) {
        log.error('TAXII objects query failed', { error: (error as Error).message });
        return taxiiResponse(c, {
            title: 'Internal Server Error',
            description: (error as Error).message,
        }, 500);
    }
});

// ============================================================================
// Add Objects (Inbound STIX ingestion) — delegates to STIX import pipeline
// ============================================================================

taxiiRouter.post('/collections/:id/objects/', taxiiAuth, async (c) => {
    const id = c.req.param('id')!; // route-guaranteed by :id pattern
    const collection = COLLECTIONS.find(col => col.id === id);

    if (!collection || !collection.can_write) {
        return taxiiResponse(c, {
            title: 'Forbidden',
            description: `Collection "${id}" does not accept writes`,
        }, 403);
    }

    let body: { objects: Array<Record<string, unknown>>;[key: string]: unknown };
    try {
        body = TaxiiInboundSchema.parse(await c.req.json());
    } catch {
        return taxiiResponse(c, {
            title: 'Bad Request',
            description: 'Request body must be a valid STIX 2.1 bundle (max 10,000 objects)',
        }, 400);
    }

    const objectCount = body.objects.length;

    log.info('TAXII inbound bundle received', { collection: id, objectCount });

    try {
        // Process the bundle inline using import logic
        const result = await importTAXIIBundle(body);

        return taxiiResponse(c, {
            id: `status--${crypto.randomUUID()}`,
            status: 'complete',
            request_timestamp: new Date().toISOString(),
            total_count: objectCount,
            success_count: result.successCount,
            failure_count: result.failureCount,
            pending_count: 0,
        }, 202);
    } catch (error) {
        return taxiiResponse(c, {
            id: `status--${crypto.randomUUID()}`,
            status: 'failed',
            request_timestamp: new Date().toISOString(),
            total_count: objectCount,
            success_count: 0,
            failure_count: objectCount,
            pending_count: 0,
        }, 500);
    }
});

// ============================================================================
// Manifest (lightweight object listing) — LIVE DATA
// ============================================================================

taxiiRouter.get('/collections/:id/manifest/', taxiiAuth, async (c) => {
    const id = c.req.param('id')!; // route-guaranteed by :id pattern
    const collection = COLLECTIONS.find(col => col.id === id);

    if (!collection || !collection.can_read) {
        return taxiiResponse(c, {
            title: 'Not Found',
            description: `Collection "${id}" not found`,
        }, 404);
    }

    try {
        const objects = await queryManifest(id);
        return taxiiResponse(c, {
            objects,
            more: false,
        });
    } catch (error) {
        return taxiiResponse(c, {
            title: 'Internal Server Error',
            description: (error as Error).message,
        }, 500);
    }
});

// ============================================================================
// Data Query Helpers
// ============================================================================

async function queryIOCsAsSTIX(
    addedAfter: string | undefined,
    limit: number,
    cursor: string | undefined,
    matchId: string | undefined,
): Promise<{ objects: Record<string, unknown>[]; more: boolean }> {
    let whereClause = 'WHERE 1=1';
    if (addedAfter) whereClause += ` AND updated_at > '${escSql(addedAfter)}'`;
    if (matchId) whereClause += ` AND id::text = '${escSql(matchId.replace(/^indicator--/, ''))}'`;
    if (cursor) whereClause += ` AND id::text > '${escSql(cursor)}'`;

    const result = await rawQuery(
        `SELECT * FROM iocs ${whereClause} ORDER BY updated_at DESC, id ASC LIMIT ${limit + 1}`
    );

    const rows = result.rows || [];
    const more = rows.length > limit;
    const data = more ? rows.slice(0, limit) : rows;

    const objects = data.map((ioc: Record<string, unknown>) => {
        const stixType = STIX_TYPE_MAP[ioc.type as string] || 'artifact';
        return {
            type: 'indicator',
            id: `indicator--${ioc.id}`,
            spec_version: '2.1',
            created: ioc.first_seen || ioc.created_at,
            modified: ioc.last_seen || ioc.updated_at,
            name: ioc.value,
            description: `${ioc.type} indicator from ${ioc.source}`,
            pattern: `[${stixType}:value = '${ioc.value}']`,
            pattern_type: 'stix',
            valid_from: ioc.first_seen || ioc.created_at,
            labels: ioc.tags || [],
            confidence: ioc.confidence || 50,
            indicator_types: ioc.threat_type ? [ioc.threat_type] : [],
            created_by_ref: PLATFORM_IDENTITY.id,
            object_marking_refs: [TLP_WHITE_MARKING.id],
        };
    });

    return { objects, more };
}

async function queryVulnsAsSTIX(
    addedAfter: string | undefined,
    limit: number,
    cursor: string | undefined,
    matchId: string | undefined,
): Promise<{ objects: Record<string, unknown>[]; more: boolean }> {
    let whereClause = 'WHERE 1=1';
    if (addedAfter) whereClause += ` AND updated_at > '${escSql(addedAfter)}'`;
    if (matchId) whereClause += ` AND cve_id = '${escSql(matchId.replace(/^vulnerability--/, ''))}'`;
    if (cursor) whereClause += ` AND id::text > '${escSql(cursor)}'`;

    const result = await rawQuery(
        `SELECT * FROM vulnerabilities ${whereClause} ORDER BY published_date DESC NULLS LAST, id ASC LIMIT ${limit + 1}`
    );

    const rows = result.rows || [];
    const more = rows.length > limit;
    const data = more ? rows.slice(0, limit) : rows;

    const objects = data.map((cve: Record<string, unknown>) => ({
        type: 'vulnerability',
        id: `vulnerability--${cve.id}`,
        spec_version: '2.1',
        created: cve.published_date || cve.created_at,
        modified: cve.updated_at,
        name: cve.cve_id,
        description: cve.description || '',
        labels: cve.severity ? [cve.severity] : [],
        external_references: [{
            source_name: 'cve',
            external_id: cve.cve_id,
            url: `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`,
        }],
        x_cvss_score: cve.cvss_score,
        created_by_ref: PLATFORM_IDENTITY.id,
        object_marking_refs: [TLP_WHITE_MARKING.id],
    }));

    return { objects, more };
}

async function queryActorsAsSTIX(
    addedAfter: string | undefined,
    limit: number,
    cursor: string | undefined,
    matchId: string | undefined,
): Promise<{ objects: Record<string, unknown>[]; more: boolean }> {
    let whereClause = 'WHERE 1=1';
    if (addedAfter) whereClause += ` AND updated_at > '${escSql(addedAfter)}'`;
    if (matchId) whereClause += ` AND id::text = '${escSql(matchId.replace(/^threat-actor--/, ''))}'`;
    if (cursor) whereClause += ` AND id::text > '${escSql(cursor)}'`;

    const result = await rawQuery(
        `SELECT * FROM threat_actors ${whereClause} ORDER BY created_at DESC NULLS LAST, id ASC LIMIT ${limit + 1}`
    );

    const rows = result.rows || [];
    const more = rows.length > limit;
    const data = more ? rows.slice(0, limit) : rows;

    const objects = data.map((actor: Record<string, unknown>) => ({
        type: 'threat-actor',
        id: `threat-actor--${actor.id}`,
        spec_version: '2.1',
        created: actor.created_at,
        modified: actor.updated_at,
        name: actor.name,
        description: actor.description || '',
        aliases: actor.aliases || [],
        sophistication: actor.sophistication,
        resource_level: actor.resource_level,
        primary_motivation: actor.primary_motivation,
        created_by_ref: PLATFORM_IDENTITY.id,
        object_marking_refs: [TLP_WHITE_MARKING.id],
    }));

    return { objects, more };
}

// ============================================================================
// Manifest Query
// ============================================================================

async function queryManifest(collectionId: string): Promise<Record<string, unknown>[]> {
    let table: string;
    let idPrefix: string;

    switch (collectionId) {
        case 'rinjani-iocs':
            table = 'iocs';
            idPrefix = 'indicator--';
            break;
        case 'rinjani-vulnerabilities':
            table = 'vulnerabilities';
            idPrefix = 'vulnerability--';
            break;
        case 'rinjani-threat-actors':
            table = 'threat_actors';
            idPrefix = 'threat-actor--';
            break;
        default:
            return [];
    }

    const result = await rawQuery(
        `SELECT id, updated_at, created_at FROM ${table} ORDER BY updated_at DESC NULLS LAST LIMIT 1000`
    );

    return (result.rows || []).map((row: Record<string, unknown>) => ({
        id: `${idPrefix}${row.id}`,
        date_added: row.created_at,
        version: row.updated_at || row.created_at,
        media_type: 'application/stix+json;version=2.1',
    }));
}

// ============================================================================
// Inbound Import (simplified — delegates to same logic as STIX pipeline)
// ============================================================================

async function importTAXIIBundle(bundle: { objects: Array<Record<string, unknown>>;[key: string]: unknown }): Promise<{
    successCount: number;
    failureCount: number;
}> {
    let successCount = 0;
    let failureCount = 0;

    for (const obj of bundle.objects) {
        try {
            if (obj.type === 'indicator' && obj.pattern) {
                const match = (obj.pattern as string).match(/\[(\S+):value\s*=\s*'([^']+)'\]/);
                if (!match) { failureCount++; continue; }

                const typeMap: Record<string, string> = {
                    'ipv4-addr': 'ip', 'ipv6-addr': 'ip', 'domain-name': 'domain',
                    'url': 'url', 'file': 'hash', 'email-addr': 'email',
                };
                const iocType = typeMap[match[1]] || 'unknown';
                const value = match[2];

                await db.execute(sql.raw(
                    `INSERT INTO iocs (type, value, source, confidence, first_seen, last_seen)
                     VALUES ('${iocType}', '${escSql(value)}', 'taxii-inbound',
                             ${obj.confidence || 50},
                             ${obj.valid_from ? `'${obj.valid_from}'` : 'NOW()'},
                             ${obj.modified ? `'${obj.modified}'` : 'NOW()'})
                     ON CONFLICT (type, value) DO UPDATE SET
                         confidence = GREATEST(iocs.confidence, EXCLUDED.confidence),
                         last_seen = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
                         updated_at = NOW()`
                ));
                successCount++;
            } else if (obj.type === 'vulnerability') {
                const cveRef = (obj.external_references as Array<Record<string, unknown>> | undefined)?.find((r: Record<string, unknown>) => r.source_name === 'cve');
                const cveId = cveRef?.external_id || obj.name || obj.id;

                await db.execute(sql.raw(
                    `INSERT INTO vulnerabilities (cve_id, description, published_date)
                     VALUES ('${escSql(String(cveId))}', '${escSql(String(obj.description || ''))}',
                             ${obj.created ? `'${obj.created}'` : 'NOW()'})
                     ON CONFLICT (cve_id) DO UPDATE SET
                         description = COALESCE(EXCLUDED.description, vulnerabilities.description),
                         updated_at = NOW()`
                ));
                successCount++;
            } else if (obj.type === 'threat-actor') {

                await db.execute(sql.raw(
                    `INSERT INTO threat_actors (name, description, sophistication, primary_motivation)
                     VALUES ('${escSql(String(obj.name || 'Unknown'))}', '${escSql(String(obj.description || ''))}',
                             ${obj.sophistication ? `'${escSql(String(obj.sophistication))}'` : 'NULL'},
                             ${obj.primary_motivation ? `'${escSql(String(obj.primary_motivation))}'` : 'NULL'})
                     ON CONFLICT (name) DO UPDATE SET
                         description = COALESCE(EXCLUDED.description, threat_actors.description),
                         updated_at = NOW()`
                ));
                successCount++;
            } else {
                // Skip metadata objects (identity, marking-definition, relationship)
                successCount++;
            }
        } catch (err) {
            failureCount++;
            log.warn(`TAXII import failed for ${obj.type}:${obj.id}`, { error: (err as Error).message });
        }
    }

    log.info('TAXII bundle imported', { successCount, failureCount });
    return { successCount, failureCount };
}

export default taxiiRouter;
