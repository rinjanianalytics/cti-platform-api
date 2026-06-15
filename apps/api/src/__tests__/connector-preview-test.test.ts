/**
 * Unit tests for the A6 builder-UI backend: previewExtract + testManifest.
 *
 * Both are pure compute (no DB, no LLM, no network) so we test the service
 * functions directly. The route handlers in routes/v1/connectors.ts are thin
 * wrappers; their request-validation paths are exercised by the route-side
 * SuggestBody/PreviewBody/TestBody zod schemas already covered.
 */

import { describe, expect, it } from 'vitest';
import { previewExtract, testManifest } from '../services/connectorPreview';

// ============================================================================
// previewExtract
// ============================================================================

describe('previewExtract — JSON sample with recordsPath', () => {
    it('returns the first N records and discovers the union of field names', () => {
        const sample = JSON.stringify({
            query_status: 'ok',
            data: [
                { ioc: '1.2.3.4', ioc_type: 'ip:port', confidence_level: 100 },
                { ioc: 'evil.example.com', ioc_type: 'domain', confidence_level: 75, tags: ['c2'] },
            ],
        });

        const result = previewExtract({
            sample,
            format: 'json',
            recordsPath: 'data',
            limit: 10,
        });

        expect(result.ok).toBe(true);
        expect(result.totalCount).toBe(2);
        expect(result.records).toHaveLength(2);
        // Union of keys across both records, sorted
        expect(result.fields).toEqual(['confidence_level', 'ioc', 'ioc_type', 'tags']);
    });

    it('limits the returned records but counts ALL extracted records in totalCount', () => {
        const sample = JSON.stringify({
            data: Array.from({ length: 25 }, (_, i) => ({ ioc: `1.2.3.${i}` })),
        });
        const result = previewExtract({
            sample, format: 'json', recordsPath: 'data', limit: 5,
        });
        expect(result.records).toHaveLength(5);
        expect(result.totalCount).toBe(25);
    });

    it('returns ok=false when recordsPath does not resolve to an array', () => {
        const sample = JSON.stringify({ query_status: 'ok', whatever: 42 });
        const result = previewExtract({
            sample, format: 'json', recordsPath: 'whatever', limit: 10,
        });
        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/array/);
        expect(result.records).toEqual([]);
    });

    it('returns ok=false on malformed JSON without throwing', () => {
        const result = previewExtract({
            sample: '{not json',
            format: 'json',
            recordsPath: 'data',
            limit: 10,
        });
        expect(result.ok).toBe(false);
        expect(result.reason).toBeDefined();
    });
});

describe('previewExtract — CSV sample with header', () => {
    it('parses header + data rows, fields = column names', () => {
        const sample = [
            'id,name,severity',
            '1,first,high',
            '2,second,medium',
            '3,third,low',
        ].join('\n');

        const result = previewExtract({
            sample,
            format: 'csv',
            csv: { delimiter: ',', hasHeader: true },
            limit: 10,
        });

        expect(result.ok).toBe(true);
        expect(result.totalCount).toBe(3);
        expect(result.records).toHaveLength(3);
        expect(result.fields).toEqual(['id', 'name', 'severity']);
        expect(result.records[0]).toEqual({ id: '1', name: 'first', severity: 'high' });
    });

    it('handles quoted commas inside fields', () => {
        const sample = [
            'id,tags,description',
            '1,"a,b,c","first, with comma"',
        ].join('\n');
        const result = previewExtract({
            sample, format: 'csv',
            csv: { delimiter: ',', hasHeader: true },
            limit: 10,
        });
        expect(result.records[0]).toEqual({
            id: '1',
            tags: 'a,b,c',
            description: 'first, with comma',
        });
    });

    it('uses positional column keys (c0, c1, …) when hasHeader=false', () => {
        const sample = '1,first,high\n2,second,low';
        const result = previewExtract({
            sample, format: 'csv',
            csv: { delimiter: ',', hasHeader: false },
            limit: 10,
        });
        expect(result.fields).toEqual(['c0', 'c1', 'c2']);
        expect(result.records[0]).toEqual({ c0: '1', c1: 'first', c2: 'high' });
    });
});

// ============================================================================
// testManifest
// ============================================================================

const VALID_IOC_MANIFEST = {
    id: 'tester',
    name: 'Test',
    enabled: true,
    entity: 'ioc',
    source: { url: 'https://example.com', method: 'GET', headers: {}, auth: { type: 'none' } },
    format: 'json',
    extract: { recordsPath: 'data' },
    mapping: {
        value: { from: 'ioc', transforms: [{ op: 'trim' }], required: true },
        type: { literal: 'ip' },
        source: { literal: 'tester' },
    },
};

const SAMPLE_PAYLOAD = JSON.stringify({
    data: [
        { ioc: '1.2.3.4' },
        { ioc: '5.6.7.8' },
    ],
});

describe('testManifest — happy path', () => {
    it('runs the engine and returns dryRun + canonical records', () => {
        const result = testManifest({
            manifest: VALID_IOC_MANIFEST,
            sample: SAMPLE_PAYLOAD,
            limit: 10,
        });
        expect(result.ok).toBe(true);
        expect(result.dryRun).toEqual({ read: 2, ok: 2, failed: 0, errors: [] });
        expect(result.records).toHaveLength(2);
        expect(result.records?.[0]).toMatchObject({ type: 'ip', value: '1.2.3.4', source: 'tester' });
    });

    it('respects the limit on records but counts all reads in dryRun', () => {
        const sample = JSON.stringify({
            data: Array.from({ length: 25 }, (_, i) => ({ ioc: `1.2.3.${i}` })),
        });
        const result = testManifest({
            manifest: VALID_IOC_MANIFEST, sample, limit: 5,
        });
        expect(result.records).toHaveLength(5);
        expect(result.dryRun?.read).toBe(25);
        expect(result.dryRun?.ok).toBe(25);
    });
});

describe('testManifest — failure paths', () => {
    it('manifest fails zod → ok=false with validationIssues', () => {
        const result = testManifest({
            manifest: { id: 'broken' }, // missing nearly everything
            sample: SAMPLE_PAYLOAD,
            limit: 10,
        });
        expect(result.ok).toBe(false);
        expect(result.validationIssues).toBeDefined();
        expect(result.validationIssues!.length).toBeGreaterThan(0);
        expect(result.dryRun).toBeUndefined();
    });

    it('transform op outside closed vocab → zod rejects → validationIssues', () => {
        const result = testManifest({
            manifest: {
                ...VALID_IOC_MANIFEST,
                mapping: {
                    value: { from: 'ioc', transforms: [{ op: 'evalJs' }], required: true },
                },
            },
            sample: SAMPLE_PAYLOAD,
            limit: 10,
        });
        expect(result.ok).toBe(false);
        expect(result.validationIssues?.some((i) => i.path.includes('op'))).toBe(true);
    });

    it('manifest valid but recordsPath misses → runtimeError, never throws', () => {
        const result = testManifest({
            manifest: {
                ...VALID_IOC_MANIFEST,
                extract: { recordsPath: 'nowhere' },
            },
            sample: SAMPLE_PAYLOAD,
            limit: 10,
        });
        expect(result.ok).toBe(false);
        expect(result.runtimeError).toMatch(/array/);
    });

    it('manifest valid, sample is malformed JSON → runtimeError', () => {
        const result = testManifest({
            manifest: VALID_IOC_MANIFEST,
            sample: '{not json',
            limit: 10,
        });
        expect(result.ok).toBe(false);
        expect(result.runtimeError).toBeDefined();
    });

    it('manifest extracts records but per-record zod fails → dryRun shows failures', () => {
        const result = testManifest({
            manifest: {
                ...VALID_IOC_MANIFEST,
                mapping: {
                    value: { from: 'ioc', required: true },
                    type: { literal: 'not-a-real-type' }, // fails IOC type enum
                    source: { literal: 'tester' },
                },
            },
            sample: SAMPLE_PAYLOAD,
            limit: 10,
        });
        expect(result.ok).toBe(true); // engine ran cleanly even though all records failed
        expect(result.dryRun?.read).toBe(2);
        expect(result.dryRun?.ok).toBe(0);
        expect(result.dryRun?.failed).toBe(2);
        expect(result.dryRun?.errors).toHaveLength(2);
        expect(result.dryRun?.errors[0]?.reason).toMatch(/type/);
    });
});
