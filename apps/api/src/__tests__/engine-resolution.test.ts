/**
 * Unit tests for resolveFeedHandler() — A3 gating logic.
 *
 * Verifies the legacy-fallback semantics promised by PLAN.md A3:
 *   "No shipped feed changes behavior" unless an operator explicitly:
 *     (a) activates a manifest for the source, AND
 *     (b) sets FEED_ENGINE_ENABLED=true globally.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the connectorStore module before importing feedRegistry so the dynamic
// import inside resolveFeedHandler sees the mock.
vi.mock('../services/connectorStore', () => ({
    listManifests: vi.fn(),
}));

// Also stub the engine handler — it has DB deps we don't want loading in
// unit tests, and the resolution layer doesn't care WHAT the handler does,
// only that it returns *something* distinguishable from the legacy entry.
vi.mock('../services/feedSync/engineHandler', () => ({
    buildEngineHandler: vi.fn(() => async () => ({
        success: true,
        pulsesProcessed: 1,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors: [],
        __engineSentinel: true, // identifies the engine handler in assertions
    })),
}));

import { resolveFeedHandler, getFeedHandler } from '../services/feedSync/feedRegistry';
import * as connectorStore from '../services/connectorStore';
import * as engineHandler from '../services/feedSync/engineHandler';

const VALID_THREATFOX_MANIFEST = {
    id: 'threatfox',
    name: 'ThreatFox',
    enabled: true,
    entity: 'ioc',
    source: { url: 'https://example.com/feed', method: 'GET', headers: {}, auth: { type: 'none' } },
    format: 'json',
    extract: { recordsPath: 'data' },
    mapping: {
        value: { from: 'ioc', required: true },
        type: { literal: 'ip', required: true },
        source: { literal: 'threatfox' },
    },
};

describe('resolveFeedHandler — A3 dispatch gating', () => {
    let originalEnv: string | undefined;

    beforeEach(() => {
        originalEnv = process.env.FEED_ENGINE_ENABLED;
        vi.clearAllMocks();
    });

    afterEach(() => {
        if (originalEnv === undefined) delete process.env.FEED_ENGINE_ENABLED;
        else process.env.FEED_ENGINE_ENABLED = originalEnv;
    });

    it('flag OFF → returns the legacy handler verbatim, no manifest lookup', async () => {
        delete process.env.FEED_ENGINE_ENABLED;

        const handler = await resolveFeedHandler('threatfox');

        expect(handler).toBe(getFeedHandler('threatfox'));
        expect(vi.mocked(connectorStore.listManifests)).not.toHaveBeenCalled();
        expect(vi.mocked(engineHandler.buildEngineHandler)).not.toHaveBeenCalled();
    });

    it('flag explicitly "false" → returns legacy handler (truthy-string only)', async () => {
        process.env.FEED_ENGINE_ENABLED = 'false';

        const handler = await resolveFeedHandler('threatfox');

        expect(handler).toBe(getFeedHandler('threatfox'));
        expect(vi.mocked(connectorStore.listManifests)).not.toHaveBeenCalled();
    });

    it('flag ON + no active manifest → returns legacy handler', async () => {
        process.env.FEED_ENGINE_ENABLED = 'true';
        vi.mocked(connectorStore.listManifests).mockResolvedValue([]);

        const handler = await resolveFeedHandler('threatfox');

        expect(handler).toBe(getFeedHandler('threatfox'));
        expect(vi.mocked(connectorStore.listManifests)).toHaveBeenCalledWith({
            source: 'threatfox',
            activeOnly: true,
        });
        expect(vi.mocked(engineHandler.buildEngineHandler)).not.toHaveBeenCalled();
    });

    it('flag ON + active IOC manifest → returns engine-backed handler', async () => {
        process.env.FEED_ENGINE_ENABLED = 'true';
        vi.mocked(connectorStore.listManifests).mockResolvedValue([
            {
                id: 'row-uuid-1',
                source: 'threatfox',
                version: 3,
                entity: 'ioc',
                manifest: VALID_THREATFOX_MANIFEST,
                isActive: true,
                createdBy: 'key:abcd1234',
                createdAt: new Date(),
                lastValidatedAt: null,
                lastValidationErrors: null,
            } as unknown as Awaited<ReturnType<typeof connectorStore.listManifests>>[number],
        ]);

        const handler = await resolveFeedHandler('threatfox');

        expect(handler).not.toBe(getFeedHandler('threatfox'));
        expect(vi.mocked(engineHandler.buildEngineHandler)).toHaveBeenCalledTimes(1);
        // First argument is the parsed manifest, second is the row id
        const callArgs = vi.mocked(engineHandler.buildEngineHandler).mock.calls[0];
        expect(callArgs[1]).toBe('row-uuid-1');
        expect(callArgs[0].id).toBe('threatfox');
        expect(callArgs[0].entity).toBe('ioc');
    });

    it('flag ON + active non-IOC manifest → falls back to legacy (A3 IOC-only scope)', async () => {
        process.env.FEED_ENGINE_ENABLED = 'true';
        vi.mocked(connectorStore.listManifests).mockResolvedValue([
            {
                id: 'row-uuid-2',
                source: 'cveorg',
                version: 1,
                entity: 'vulnerability',
                manifest: { ...VALID_THREATFOX_MANIFEST, entity: 'vulnerability' },
                isActive: true,
                createdBy: 'jwt-user',
                createdAt: new Date(),
                lastValidatedAt: null,
                lastValidationErrors: null,
            } as unknown as Awaited<ReturnType<typeof connectorStore.listManifests>>[number],
        ]);

        const handler = await resolveFeedHandler('cveorg');

        expect(handler).toBe(getFeedHandler('cveorg'));
        expect(vi.mocked(engineHandler.buildEngineHandler)).not.toHaveBeenCalled();
    });

    it('flag ON + corrupt manifest body (fails engine zod) → falls back to legacy', async () => {
        process.env.FEED_ENGINE_ENABLED = 'true';
        vi.mocked(connectorStore.listManifests).mockResolvedValue([
            {
                id: 'row-uuid-3',
                source: 'threatfox',
                version: 9,
                entity: 'ioc',
                // Missing required `source.url`, `format`, `extract`, `mapping`
                manifest: { id: 'corrupt', name: 'corrupt', entity: 'ioc' } as Record<string, unknown>,
                isActive: true,
                createdBy: 'key:zzzz9999',
                createdAt: new Date(),
                lastValidatedAt: null,
                lastValidationErrors: null,
            } as unknown as Awaited<ReturnType<typeof connectorStore.listManifests>>[number],
        ]);

        const handler = await resolveFeedHandler('threatfox');

        expect(handler).toBe(getFeedHandler('threatfox'));
        expect(vi.mocked(engineHandler.buildEngineHandler)).not.toHaveBeenCalled();
    });

    it('flag ON + DB lookup throws → falls back to legacy (never breaks the worker)', async () => {
        process.env.FEED_ENGINE_ENABLED = 'true';
        vi.mocked(connectorStore.listManifests).mockRejectedValue(new Error('postgres connection refused'));

        const handler = await resolveFeedHandler('threatfox');

        expect(handler).toBe(getFeedHandler('threatfox'));
        expect(vi.mocked(engineHandler.buildEngineHandler)).not.toHaveBeenCalled();
    });

    it('unknown source + flag OFF → returns undefined (worker raises Unknown feed source)', async () => {
        delete process.env.FEED_ENGINE_ENABLED;
        const handler = await resolveFeedHandler('not-a-real-feed');
        expect(handler).toBeUndefined();
    });

    it('unknown source + flag ON + no manifest → returns undefined', async () => {
        process.env.FEED_ENGINE_ENABLED = 'true';
        vi.mocked(connectorStore.listManifests).mockResolvedValue([]);
        const handler = await resolveFeedHandler('not-a-real-feed');
        expect(handler).toBeUndefined();
    });
});
