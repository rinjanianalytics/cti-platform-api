/**
 * Unit tests for draftMapper — A5 of the declarative connector engine.
 *
 * Verifies the five "never-stub" guarantees from PLAN.md:
 *   1. No LLM provider → deterministic skeleton + reason
 *   2. LLM returns non-JSON → skeleton + reason
 *   3. LLM JSON fails FeedManifest zod → skeleton + reason
 *   4. LLM emits wrong entity → skeleton + reason
 *   5. Engine dry-run produces zero records → LLM's manifest (not skeleton)
 *      + status='couldnt_map' + dry-run errors
 *
 * Plus the happy path: LLM returns runnable manifest → status='ok' + dryRun
 * stats with ok > 0.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/aiMiddleware/callLLM', () => ({
    callLLM: vi.fn(),
}));

import { draftMapper, buildSkeleton, buildPrompt } from '../services/draftMapper';
import { callLLM } from '../services/aiMiddleware/callLLM';

const sampleThreatFox = JSON.stringify({
    query_status: 'ok',
    data: [
        { ioc: '1.2.3.4:80', ioc_type: 'ip:port', confidence_level: 100, first_seen: '2026-06-15 00:00:00 UTC' },
        { ioc: 'evil.example.com', ioc_type: 'domain', confidence_level: 75, first_seen: '2026-06-15 01:00:00 UTC' },
    ],
});

const RUNNABLE_IOC_MANIFEST = {
    id: 'threatfox',
    name: 'ThreatFox',
    enabled: true,
    entity: 'ioc',
    source: { url: 'https://example.com/feed', method: 'GET', headers: {}, auth: { type: 'none' } },
    format: 'json',
    extract: { recordsPath: 'data' },
    mapping: {
        value: { from: 'ioc', transforms: [{ op: 'trim' }], required: true },
        type: {
            from: 'ioc_type',
            transforms: [
                { op: 'mapEnum', arg: { table: { 'ip:port': 'ip', 'domain': 'domain' }, fallback: 'unknown' } },
            ],
            required: true,
        },
        source: { literal: 'threatfox' },
    },
};

const baseInput = {
    sample: sampleThreatFox,
    format: 'json' as const,
    entity: 'ioc' as const,
    sourceName: 'threatfox',
};

beforeEach(() => {
    vi.clearAllMocks();
});

afterEach(() => {
    vi.resetAllMocks();
});

describe('buildSkeleton — empty starter manifest', () => {
    it('produces an enabled=false IOC skeleton with empty mapping', () => {
        const s = buildSkeleton({
            ...baseInput,
            sample: '{}',
        });
        expect(s.enabled).toBe(false);
        expect(s.entity).toBe('ioc');
        expect(s.mapping).toEqual({});
        expect(s.source.url).toMatch(/REPLACE-ME/);
        expect(s.format).toBe('json');
    });

    it('chooses CSV extract config for CSV format', () => {
        const s = buildSkeleton({ ...baseInput, sample: 'a,b,c', format: 'csv' });
        expect(s.extract).toEqual({ csv: { delimiter: ',', hasHeader: true } });
    });

    it('honours recordsPathHint when provided', () => {
        const s = buildSkeleton({ ...baseInput, recordsPathHint: 'records.nested.items' });
        expect(s.extract).toMatchObject({ recordsPath: 'records.nested.items' });
    });
});

describe('buildPrompt — content audit', () => {
    it('includes the closed transform vocab so the LLM is constrained', () => {
        const p = buildPrompt(baseInput);
        for (const op of ['mapEnum', 'bucketize', 'prepend', 'toIso', 'regexExtract']) {
            expect(p).toContain(op);
        }
    });

    it('embeds the operator-provided sourceName as the literal anchor', () => {
        const p = buildPrompt({ ...baseInput, sourceName: 'newfeed-2026' });
        expect(p).toContain('"newfeed-2026"');
    });

    it('truncates very large samples with a documented marker', () => {
        const huge = 'x'.repeat(20_000);
        const p = buildPrompt({ ...baseInput, sample: huge });
        expect(p).toContain('truncated; original 20000 bytes');
    });

    it('describes the target entity required fields verbatim', () => {
        const ioc = buildPrompt({ ...baseInput, entity: 'ioc' });
        expect(ioc).toContain('"hash-sha256"');

        const vuln = buildPrompt({ ...baseInput, entity: 'vulnerability' });
        expect(vuln).toContain('cveId');
        expect(vuln).toContain('CVE-');
    });
});

describe('draftMapper — happy path', () => {
    it('returns status=ok + dryRun.ok > 0 when LLM emits a runnable manifest', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: JSON.stringify(RUNNABLE_IOC_MANIFEST),
            provider: 'gemini', model: 'gemini-2.0-flash',
            latencyMs: 234, tokensUsed: 412,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('ok');
        expect(result.manifest.mapping).toHaveProperty('value');
        expect(result.dryRun?.ok).toBeGreaterThan(0);
        expect(result.dryRun?.read).toBe(2);
        expect(result.llmMeta?.provider).toBe('gemini');
    });

    it('strips markdown code fences when the LLM ignores jsonMode and wraps the JSON', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: '```json\n' + JSON.stringify(RUNNABLE_IOC_MANIFEST) + '\n```',
            provider: 'openrouter', model: 'meta-llama/llama-3.1-70b-instruct',
            latencyMs: 1100, tokensUsed: 380,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('ok');
        expect(result.dryRun?.ok).toBeGreaterThan(0);
    });
});

describe('draftMapper — five never-stub guarantees', () => {
    it('GUARANTEE 1: no LLM provider → skeleton + reason; never throws', async () => {
        vi.mocked(callLLM).mockRejectedValue(new Error('no providers reachable'));

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        expect(result.manifest.mapping).toEqual({});
        expect(result.manifest.enabled).toBe(false);
        expect(result.reason).toMatch(/LLM unavailable/);
        expect(result.dryRun).toBeUndefined();
    });

    it('GUARANTEE 2: LLM returns non-JSON → skeleton + parse-error reason', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: 'Sure! Here is your manifest: it would parse the ioc field...',
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 200,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        expect(result.manifest.mapping).toEqual({});
        expect(result.reason).toMatch(/did not return valid JSON/);
        expect(result.llmMeta?.provider).toBe('gemini'); // meta still surfaced
    });

    it('GUARANTEE 3a: LLM JSON fails zod (missing required fields) → skeleton + schema reason', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: JSON.stringify({ id: 'x', entity: 'ioc' }), // missing most fields
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 200,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        expect(result.manifest.mapping).toEqual({}); // skeleton
        expect(result.reason).toMatch(/manifest schema/);
    });

    it('GUARANTEE 3b: LLM emits a transform op outside the closed vocab → zod rejects → skeleton', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: JSON.stringify({
                ...RUNNABLE_IOC_MANIFEST,
                mapping: {
                    value: { from: 'ioc', transforms: [{ op: 'evalJs', arg: 'value.toUpperCase()' }], required: true },
                    type: { literal: 'ip' }, source: { literal: 'threatfox' },
                },
            }),
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 200,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        expect(result.manifest.mapping).toEqual({});
        expect(result.reason).toMatch(/manifest schema/);
    });

    it('GUARANTEE 4: LLM emits wrong entity → skeleton + entity-mismatch reason', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: JSON.stringify({ ...RUNNABLE_IOC_MANIFEST, entity: 'vulnerability' }),
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 200,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        expect(result.manifest.mapping).toEqual({}); // skeleton, not the bogus output
        expect(result.reason).toMatch(/vulnerability.*ioc/);
    });

    it('GUARANTEE 5: dry-run produces zero records → return LLM manifest (not skeleton) for editing + dryRun errors', async () => {
        const wrongPathManifest = {
            ...RUNNABLE_IOC_MANIFEST,
            // recordsPath points at a non-existent field → extractor will throw,
            // engine catches at the outer level. Use a manifest that parses but
            // fails per-record instead: missing required `value` field source.
            mapping: {
                value: { from: 'nonexistent_field', transforms: [{ op: 'trim' }], required: true },
                type: { literal: 'ip' }, source: { literal: 'threatfox' },
            },
        };
        vi.mocked(callLLM).mockResolvedValue({
            text: JSON.stringify(wrongPathManifest),
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 200,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        // KEY DIFFERENCE from other failures: the LLM manifest is returned
        // (so the UI can show it for editing), NOT the empty skeleton.
        expect(result.manifest.mapping).toHaveProperty('value');
        expect(result.reason).toMatch(/zero records/);
        expect(result.dryRun?.ok).toBe(0);
        expect(result.dryRun?.failed).toBe(2);
        expect(result.dryRun?.errors[0]?.reason).toMatch(/required field "value" empty/);
    });
});

describe('draftMapper — explicit LLM-declines envelope', () => {
    it('honours the {"error": "..."} contract from the prompt → skeleton + declined reason', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: JSON.stringify({ error: 'sample is HTML, not JSON' }),
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 200,
        });

        const result = await draftMapper(baseInput);

        expect(result.status).toBe('couldnt_map');
        expect(result.manifest.mapping).toEqual({});
        expect(result.reason).toMatch(/declined.*HTML/);
    });
});
