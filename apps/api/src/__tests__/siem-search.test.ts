/**
 * SIEM search adapter tests (AA.5 / Phase 10).
 *
 * Builds a read-only, size-capped, time-bounded _search; rejects non-read
 * queries; fails gracefully when no SIEM is wired; parses ES/OpenSearch hits.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { siemSearch, isSiemConfigured } from '../services/siemSearch';

interface FetchInit { method?: string; headers?: Record<string, string>; body?: string }

function stubFetch(impl: (url: string, init?: FetchInit) => Promise<unknown>) {
    const fetchMock = vi.fn(impl);
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
}

const ES_OK = {
    took: 7,
    hits: { total: { value: 2 }, hits: [{ _source: { src_ip: '1.2.3.4' } }, { _source: { src_ip: '5.6.7.8' } }] },
};

beforeEach(() => { process.env.SIEM_URL = 'https://siem.internal:9200'; });
afterEach(() => {
    delete process.env.SIEM_URL;
    delete process.env.SIEM_INDEX;
    delete process.env.SIEM_API_KEY;
    vi.unstubAllGlobals();
});

describe('siemSearch', () => {
    it('builds a read-only _search (query_string + size + time range) and parses hits', async () => {
        const fetchMock = stubFetch(async () => ({ ok: true, json: async () => ES_OK }));
        const r = await siemSearch({ query: 'src_ip:1.2.3.4', size: 50, sinceHours: 24 });

        expect(r.total).toBe(2);
        expect(r.hits).toHaveLength(2);
        expect(r.hits[0]).toEqual({ src_ip: '1.2.3.4' });

        const [url, init] = fetchMock.mock.calls[0];
        expect(url).toContain('/logs-*/_search'); // default index 'logs-*' (wildcard kept literal for ES)
        const body = JSON.parse((init as FetchInit).body as string) as { size: number; query: { bool: { must: unknown[] } } };
        expect(body.size).toBe(50);
        expect(body.query.bool.must).toHaveLength(2); // query_string + range
    });

    it('caps size at 100', async () => {
        const fetchMock = stubFetch(async () => ({ ok: true, json: async () => ES_OK }));
        await siemSearch({ query: 'x', size: 9999 });
        const body = JSON.parse((fetchMock.mock.calls[0][1] as FetchInit).body as string) as { size: number };
        expect(body.size).toBe(100);
    });

    it('sends an ApiKey header when SIEM_API_KEY is set', async () => {
        process.env.SIEM_API_KEY = 'sekret';
        const fetchMock = stubFetch(async () => ({ ok: true, json: async () => ES_OK }));
        await siemSearch({ query: 'x' });
        expect((fetchMock.mock.calls[0][1] as FetchInit).headers?.Authorization).toBe('ApiKey sekret');
    });

    it('rejects a non-read query (defense in depth)', async () => {
        const fetchMock = stubFetch(async () => ({ ok: true, json: async () => ES_OK }));
        await expect(siemSearch({ query: 'foo _delete_by_query' })).rejects.toThrow(/read-only/);
        await expect(siemSearch({ query: 'a script b' })).rejects.toThrow(/read-only/);
        expect(fetchMock).not.toHaveBeenCalled(); // never fired
    });

    it('fails gracefully when no SIEM is configured (placeholder mode)', async () => {
        delete process.env.SIEM_URL;
        await expect(siemSearch({ query: 'x' })).rejects.toThrow(/not configured/);
    });

    it('throws on a non-ok response with status', async () => {
        stubFetch(async () => ({ ok: false, status: 503, text: async () => 'unavailable' }));
        await expect(siemSearch({ query: 'x' })).rejects.toThrow(/SIEM 503/);
    });

    it('isSiemConfigured reflects SIEM_URL', () => {
        expect(isSiemConfigured()).toBe(true);
        delete process.env.SIEM_URL;
        expect(isSiemConfigured()).toBe(false);
    });
});
