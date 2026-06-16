/**
 * Arkham adapter tests (AA.6.3).
 *
 * Parses the LIVE response shape probed 2026-06-16 (the #141 verify-first
 * lesson). Confirms: attribution extraction, the API-Key header + endpoint,
 * the unconfigured + non-ok error paths, and the unattributed flag.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { lookupAddress, isArkhamConfigured } from '../services/arkham';

const VITALIK = {
    address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
    chain: 'ethereum',
    arkhamEntity: { name: 'Vitalik Buterin', type: 'individual', id: 'vitalik-buterin', service: null },
    arkhamLabel: { name: 'vitalik.eth', chainType: 'evm' },
    isUserAddress: false,
    contract: false,
};

function stubFetch(impl: (url: string, init?: RequestInit) => Promise<unknown>) {
    const fetchMock = vi.fn(impl);
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
}

beforeEach(() => { process.env.ARKHAM_API_KEY = 'test-key'; });
afterEach(() => {
    delete process.env.ARKHAM_API_KEY;
    delete process.env.ARKHAM_API_URL;
    vi.unstubAllGlobals();
});

describe('lookupAddress', () => {
    it('extracts attribution from the live Arkham response shape', async () => {
        stubFetch(async () => ({ ok: true, json: async () => VITALIK }));
        const a = await lookupAddress('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', 'ethereum');
        expect(a.entityName).toBe('Vitalik Buterin');
        expect(a.entityType).toBe('individual');
        expect(a.entityId).toBe('vitalik-buterin');
        expect(a.label).toBe('vitalik.eth');
        expect(a.unattributed).toBe(false);
    });

    it('sends the API-Key header to the address-intelligence endpoint', async () => {
        const fetchMock = stubFetch(async () => ({ ok: true, json: async () => VITALIK }));
        await lookupAddress('0xabc', 'ethereum');
        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toContain('/intelligence/address/0xabc');
        expect(url).toContain('chain=ethereum');
        expect((init as { headers: Record<string, string> }).headers['API-Key']).toBe('test-key');
    });

    it('honours ARKHAM_API_URL override', async () => {
        process.env.ARKHAM_API_URL = 'https://arkham.internal';
        const fetchMock = stubFetch(async () => ({ ok: true, json: async () => VITALIK }));
        await lookupAddress('0xabc');
        expect(fetchMock.mock.calls[0][0]).toContain('https://arkham.internal/intelligence/address/0xabc');
    });

    it('marks an address with no entity/label as unattributed', async () => {
        stubFetch(async () => ({ ok: true, json: async () => ({ address: '0x', chain: 'ethereum', arkhamEntity: null, arkhamLabel: null, isUserAddress: true, contract: false }) }));
        const a = await lookupAddress('0x', 'ethereum');
        expect(a.unattributed).toBe(true);
        expect(a.entityName).toBeNull();
    });

    it('throws when ARKHAM_API_KEY is unset (BYO-key, graceful)', async () => {
        delete process.env.ARKHAM_API_KEY;
        await expect(lookupAddress('0xabc')).rejects.toThrow(/not configured/);
    });

    it('throws on a non-ok response with the status', async () => {
        stubFetch(async () => ({ ok: false, status: 403, text: async () => 'forbidden' }));
        await expect(lookupAddress('0xabc')).rejects.toThrow(/Arkham 403/);
    });
});

describe('isArkhamConfigured', () => {
    it('reflects ARKHAM_API_KEY presence', () => {
        expect(isArkhamConfigured()).toBe(true);
        delete process.env.ARKHAM_API_KEY;
        expect(isArkhamConfigured()).toBe(false);
    });
});
