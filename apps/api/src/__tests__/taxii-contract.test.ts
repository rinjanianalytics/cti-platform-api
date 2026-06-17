/**
 * TAXII 2.1 contract-conformance tests.
 *
 * Locks the public interop surface so a refactor can't silently break a
 * downstream STIX consumer (OpenCTI, MISP, TheHive, a CERT). Runs IN-PROCESS
 * via `taxiiRouter.request()` — no live server, no Postgres — by exercising
 * only the paths that resolve before any DB query:
 *   - Discovery / Collections / Collection (pure, in-memory)
 *   - auth gating (401 returns before the DB lookup)
 *   - write-protection (403), body validation (400), read-protection (404)
 *     all run before the handler touches the database.
 *
 * The DB-backed success paths (objects/manifest bodies) are intentionally NOT
 * covered here — they belong in the infra-backed integration suite.
 *
 * KNOWN CONFORMANCE GAPS (documented, deliberately NOT asserted as "correct"
 * here so this suite doesn't ossify them — tracked for a follow-up that needs
 * the integration harness + a consumer-impact call):
 *   1. GET .../objects/ returns a STIX `bundle` ({type,id,objects,more}); TAXII
 *      2.1 §5.4 specifies an Envelope ({more,next?,objects}).
 *   2. No distinct API-Root resource ({title,versions,max_content_length}) —
 *      Discovery and the api-root share the `/taxii2/` path.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import taxiiRouter from '../routes/taxii';

const TAXII_CT = 'application/taxii+json;version=2.1';
const TOKEN = 'test-taxii-token';

beforeAll(() => { process.env.TAXII_API_KEY = TOKEN; });

const req = (path: string, init?: RequestInit) => taxiiRouter.request(path, init);
const authd = (path: string, init: RequestInit = {}) =>
    taxiiRouter.request(path, { ...init, headers: { Authorization: `Bearer ${TOKEN}`, ...(init.headers ?? {}) } });

describe('TAXII 2.1 contract conformance', () => {
    describe('Discovery — GET /', () => {
        it('200 with the TAXII media type and the required discovery fields', async () => {
            const res = await req('/');
            expect(res.status).toBe(200);
            expect(res.headers.get('content-type')).toContain(TAXII_CT);
            const d = await res.json();
            expect(d).toMatchObject({
                title: expect.any(String),
                description: expect.any(String),
                api_roots: expect.any(Array),
            });
            expect(d.api_roots.length).toBeGreaterThan(0);
            expect(typeof d.default).toBe('string');
        });
    });

    describe('Collections — GET /collections/', () => {
        it('200 + a collections[] where each entry carries every required TAXII field', async () => {
            const res = await req('/collections/');
            expect(res.status).toBe(200);
            expect(res.headers.get('content-type')).toContain(TAXII_CT);
            const d = await res.json();
            expect(Array.isArray(d.collections)).toBe(true);
            expect(d.collections.length).toBeGreaterThan(0);
            for (const col of d.collections) {
                expect(col).toMatchObject({
                    id: expect.any(String),
                    title: expect.any(String),
                    can_read: expect.any(Boolean),
                    can_write: expect.any(Boolean),
                    media_types: expect.any(Array),
                });
                expect(col.media_types).toContain('application/stix+json;version=2.1');
            }
        });

        it('exposes at least one readable and one writable collection', async () => {
            const d = await (await req('/collections/')).json();
            expect(d.collections.some((c: { can_read: boolean }) => c.can_read)).toBe(true);
            expect(d.collections.some((c: { can_write: boolean }) => c.can_write)).toBe(true);
        });
    });

    describe('Collection — GET /collections/:id', () => {
        it('200 for a known collection, shaped like a collection resource', async () => {
            const res = await req('/collections/rinjani-iocs');
            expect(res.status).toBe(200);
            const d = await res.json();
            expect(d.id).toBe('rinjani-iocs');
            expect(d).toHaveProperty('can_read');
            expect(d).toHaveProperty('can_write');
        });

        it('404 with the TAXII media type for an unknown collection', async () => {
            const res = await req('/collections/does-not-exist');
            expect(res.status).toBe(404);
            expect(res.headers.get('content-type')).toContain(TAXII_CT);
            const d = await res.json();
            expect(d.title).toBeDefined();
        });
    });

    describe('Authentication — data endpoints require a Bearer token', () => {
        it('GET objects without a token → 401 UNAUTHORIZED', async () => {
            const res = await req('/collections/rinjani-iocs/objects/');
            expect(res.status).toBe(401);
            expect(res.headers.get('content-type')).toContain(TAXII_CT);
            expect((await res.json()).error_code).toBe('UNAUTHORIZED');
        });

        it('GET manifest without a token → 401', async () => {
            expect((await req('/collections/rinjani-iocs/manifest/')).status).toBe(401);
        });

        it('POST objects without a token → 401', async () => {
            expect((await req('/collections/rinjani-inbound/objects/', { method: 'POST' })).status).toBe(401);
        });

        it('a non-Bearer Authorization header → 401', async () => {
            const res = await req('/collections/rinjani-iocs/objects/', { headers: { Authorization: 'Token abc' } });
            expect(res.status).toBe(401);
        });
    });

    describe('Authorization — pre-DB write/read guards (token valid)', () => {
        it('POST to a read-only collection → 403', async () => {
            const res = await authd('/collections/rinjani-iocs/objects/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: 'bundle', objects: [] }),
            });
            expect(res.status).toBe(403);
            expect(res.headers.get('content-type')).toContain(TAXII_CT);
        });

        it('POST a malformed bundle to a writable collection → 400', async () => {
            const res = await authd('/collections/rinjani-inbound/objects/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ not: 'a bundle' }),
            });
            expect(res.status).toBe(400);
        });

        it('GET objects on a non-readable collection → 404', async () => {
            expect((await authd('/collections/rinjani-inbound/objects/')).status).toBe(404);
        });

        it('GET objects on an unknown collection → 404', async () => {
            expect((await authd('/collections/nope/objects/')).status).toBe(404);
        });
    });
});
