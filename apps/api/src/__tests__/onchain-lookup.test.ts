/**
 * Free on-chain attribution aggregator tests (replaces arkham.test.ts).
 *
 * Verifies multi-source merge + precedence + graceful degradation, with the
 * DB layer and `fetch` mocked. MistTrack stays off (no key) so the no-key path
 * is exercised by default.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const getWalletByRef = vi.fn();
vi.mock('../services/onchainStore', () => ({ getWalletByRef: (...a: unknown[]) => getWalletByRef(...a) }));

import { lookupAddress } from '../services/onchainLookup';

const UNI = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';

function mockFetch(handlers: Record<string, unknown>) {
    return vi.fn(async (url: string) => {
        const key = Object.keys(handlers).find(k => url.includes(k));
        if (!key) return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
        return { ok: true, status: 200, json: async () => handlers[key], text: async () => '' };
    });
}

describe('onchain lookup aggregator', () => {
    beforeEach(() => {
        getWalletByRef.mockReset();
        delete process.env.MISTTRACK_API_KEY;
    });
    afterEach(() => vi.unstubAllGlobals());

    it('merges Blockscout (is_contract) + DefiLlama (protocol) with correct precedence', async () => {
        getWalletByRef.mockResolvedValue(null); // no DB hit
        vi.stubGlobal('fetch', mockFetch({
            '/api/v2/addresses/': { name: 'UniswapV2Router02', is_contract: true },
            'api.llama.fi/protocols': [{ name: 'Uniswap', address: UNI, category: 'Dexes' }],
        }));

        const r = await lookupAddress(UNI, 'ethereum');

        // DefiLlama outranks Blockscout for the entity name; Blockscout supplies is_contract.
        expect(r.entityName).toBe('Uniswap');
        expect(r.entityType).toBe('defi');
        expect(r.isContract).toBe(true);
        expect(r.tags).toContain('dexes');
        expect(r.sources.map(s => s.source).sort()).toEqual(['blockscout', 'defillama']);
        expect(r.unattributed).toBe(false);
    });

    it('lets our DB attribution win over external sources', async () => {
        getWalletByRef.mockResolvedValue({
            entityLabel: 'Lazarus Group', entityType: 'sanctioned', confidence: 100,
            riskTags: ['sanctioned', 'ofac-sdn'], attributionSource: 'ofac', name: null,
        });
        vi.stubGlobal('fetch', mockFetch({
            '/api/v2/addresses/': { name: 'SomeContract', is_contract: true },
        }));

        const r = await lookupAddress('0x1111111111111111111111111111111111111111', 'ethereum');
        expect(r.entityName).toBe('Lazarus Group');
        expect(r.entityType).toBe('sanctioned');
        expect(r.confidence).toBe(100);
        expect(r.sources[0].source).toBe('ofac');
    });

    it('returns unattributed (never throws) when every source is empty', async () => {
        getWalletByRef.mockResolvedValue(null);
        vi.stubGlobal('fetch', mockFetch({})); // all 404

        const r = await lookupAddress('0x2222222222222222222222222222222222222222', 'ethereum');
        expect(r.unattributed).toBe(true);
        expect(r.entityName).toBeNull();
        expect(r.sources).toEqual([]);
    });
});
