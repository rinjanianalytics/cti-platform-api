/**
 * Unit tests for the /v1/connectors validation + manifest-body checks.
 * Service-layer DB ops aren't covered here (project convention: pure unit
 * tests over schemas, integration is verified by curl-style smoke tests).
 */

import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateManifestBody } from '../services/connectorStore';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..', '..', '..', '..');
const exampleManifest = (name: string) =>
    JSON.parse(readFileSync(resolve(repoRoot, 'packages/feed-engine/manifests', `${name}.json`), 'utf8'));

// Re-derive the request-body schema here. Keeping the test schema-level
// instead of importing from the route module avoids pulling Hono into a
// pure unit test.
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

describe('validateManifestBody — engine schema enforcement', () => {
    it('accepts the ThreatFox example manifest', () => {
        const result = validateManifestBody(exampleManifest('threatfox'));
        expect(result.ok).toBe(true);
    });

    it('accepts the URLhaus example manifest', () => {
        const result = validateManifestBody(exampleManifest('urlhaus'));
        expect(result.ok).toBe(true);
    });

    it('rejects a manifest missing required entity field', () => {
        const result = validateManifestBody({
            id: 'broken',
            name: 'broken',
            enabled: true,
            // entity missing
            source: { url: 'https://example.com' },
            format: 'json',
            extract: {},
            mapping: {},
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.errors.some((e) => e.path.includes('entity'))).toBe(true);
        }
    });

    it('rejects an entity value outside the canonical enum', () => {
        const result = validateManifestBody({
            id: 'bad-entity',
            name: 'bad',
            enabled: true,
            entity: 'galaxy_cluster', // intentionally not in the engine enum
            source: { url: 'https://example.com' },
            format: 'json',
            extract: {},
            mapping: {},
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.errors.some((e) => e.path.includes('entity'))).toBe(true);
        }
    });

    it('rejects an invalid source URL', () => {
        const result = validateManifestBody({
            id: 'bad-url',
            name: 'bad',
            enabled: true,
            entity: 'ioc',
            source: { url: 'not-a-url' },
            format: 'json',
            extract: {},
            mapping: { value: { from: 'x', required: true } },
        });
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.errors.some((e) => e.path.includes('source.url'))).toBe(true);
        }
    });

    it('returns structured per-field errors not just a single message', () => {
        const result = validateManifestBody({ id: 'sparse' }); // many fields missing
        expect(result.ok).toBe(false);
        if (!result.ok) {
            expect(result.errors.length).toBeGreaterThan(2);
            for (const e of result.errors) {
                expect(typeof e.path).toBe('string');
                expect(typeof e.message).toBe('string');
            }
        }
    });
});

describe('CreateBody — POST /v1/connectors request schema', () => {
    it('accepts a minimal valid body', () => {
        const result = CreateBody.safeParse({
            source: 'threatfox',
            entity: 'ioc',
            manifest: { id: 'threatfox', entity: 'ioc' },
        });
        expect(result.success).toBe(true);
    });

    it('rejects empty source', () => {
        const result = CreateBody.safeParse({ source: '', entity: 'ioc', manifest: {} });
        expect(result.success).toBe(false);
    });

    it('rejects source longer than 100 chars (matches DB varchar(100))', () => {
        const result = CreateBody.safeParse({
            source: 'a'.repeat(101),
            entity: 'ioc',
            manifest: {},
        });
        expect(result.success).toBe(false);
    });

    it('rejects entity longer than 50 chars (matches DB varchar(50))', () => {
        const result = CreateBody.safeParse({
            source: 'x',
            entity: 'a'.repeat(51),
            manifest: {},
        });
        expect(result.success).toBe(false);
    });

    it('rejects when manifest is not an object', () => {
        const result = CreateBody.safeParse({
            source: 'x',
            entity: 'ioc',
            manifest: 'string-not-object',
        });
        expect(result.success).toBe(false);
    });
});

describe('ListQuery — GET /v1/connectors query schema', () => {
    it('accepts all-empty (returns full list)', () => {
        const result = ListQuery.safeParse({});
        expect(result.success).toBe(true);
    });

    it('accepts activeOnly=true / false as the only literal forms', () => {
        expect(ListQuery.safeParse({ activeOnly: 'true' }).success).toBe(true);
        expect(ListQuery.safeParse({ activeOnly: 'false' }).success).toBe(true);
    });

    it('rejects activeOnly with non-literal values', () => {
        expect(ListQuery.safeParse({ activeOnly: '1' }).success).toBe(false);
        expect(ListQuery.safeParse({ activeOnly: 'yes' }).success).toBe(false);
    });
});
