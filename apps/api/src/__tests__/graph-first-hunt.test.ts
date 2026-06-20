/**
 * Graph-first SIEM hunt tests (PLAN B3 / Phase 9–10).
 *
 * Locks the deterministic glue: indicator extraction from Cypher rows, Lucene
 * synthesis, the graph-first → fallback → read-only-search → correlate pipeline,
 * and the honest "SIEM not configured" degrade.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/nlCypher', () => ({ nlToCypherQuery: vi.fn() }));
vi.mock('../services/siemSearch', () => ({ siemSearch: vi.fn(), isSiemConfigured: vi.fn() }));

import { graphFirstHunt, __testing } from '../services/graphFirstHunt';
import { nlToCypherQuery } from '../services/nlCypher';
import { siemSearch, isSiemConfigured } from '../services/siemSearch';

const { extractIndicators, synthesizeSiemQuery, looksLikeIndicator } = __testing;
const mockNl = vi.mocked(nlToCypherQuery);
const mockSearch = vi.mocked(siemSearch);
const mockConfigured = vi.mocked(isSiemConfigured);

const nlOk = (records: Record<string, unknown>[]) => ({ question: 'q', cypher: 'MATCH (n) RETURN n', records, success: true as const, meta: {} as never });

afterEach(() => vi.clearAllMocks());

describe('extractIndicators', () => {
    it('pulls IP / domain / hash / URL out of arbitrary rows, deduped', () => {
        const out = extractIndicators([
            { ioc: { value: '1.2.3.4' } },
            { value: 'evil-c2.com' },
            { hash: 'd41d8cd98f00b204e9800998ecf8427e' },
            { url: 'https://bad.example/payload' },
            { dup: '1.2.3.4' },
        ]);
        expect(out).toContain('1.2.3.4');
        expect(out).toContain('evil-c2.com');
        expect(out).toContain('d41d8cd98f00b204e9800998ecf8427e');
        expect(out).toContain('https://bad.example/payload');
        expect(out.filter((x) => x === '1.2.3.4')).toHaveLength(1); // deduped
    });

    it('ignores non-indicator strings and static-asset domains', () => {
        expect(looksLikeIndicator('Salt Typhoon')).toBe(false);
        expect(looksLikeIndicator('app.bundle.js')).toBe(false);
        expect(looksLikeIndicator('999.999.999.999')).toBe(false);
        expect(extractIndicators([{ name: 'Emotet', note: 'a campaign' }])).toEqual([]);
    });
});

describe('synthesizeSiemQuery', () => {
    it('OR-joins quoted indicators and strips quotes/backslashes', () => {
        expect(synthesizeSiemQuery(['1.2.3.4', 'evil.com'])).toBe('"1.2.3.4" OR "evil.com"');
        expect(synthesizeSiemQuery(['a"b\\c'])).toBe('"abc"');
    });
});

describe('graphFirstHunt', () => {
    it('graph-first: expands indicators, searches, correlates the ones seen in telemetry', async () => {
        mockNl.mockResolvedValue(nlOk([{ value: '1.2.3.4' }, { value: 'evil.com' }]));
        mockConfigured.mockReturnValue(true);
        mockSearch.mockResolvedValue({ total: 1, hits: [{ src_ip: '1.2.3.4', msg: 'beacon' }], tookMs: 5, index: 'logs-*' });

        const r = await graphFirstHunt({ question: 'hosts talking to known C2?' });
        expect(r.graph.indicators).toEqual(['1.2.3.4', 'evil.com']);
        expect(r.graph.usedFallback).toBe(false);
        expect(mockSearch).toHaveBeenCalledOnce();
        expect(r.siem.query).toBe('"1.2.3.4" OR "evil.com"');
        expect(r.correlated).toEqual(['1.2.3.4']); // only the IP showed up in hits
    });

    it('falls back to seed indicators when the graph has no signal', async () => {
        mockNl.mockResolvedValue(nlOk([]));
        mockConfigured.mockReturnValue(false);

        const r = await graphFirstHunt({ question: 'anything', seedIndicators: ['9.9.9.9'] });
        expect(r.graph.usedFallback).toBe(true);
        expect(r.graph.indicators).toEqual(['9.9.9.9']);
        expect(r.siem.configured).toBe(false);
        expect(r.siem.query).toBe('"9.9.9.9"');     // query still synthesized, just not fired
        expect(mockSearch).not.toHaveBeenCalled();
    });

    it('stops honestly when neither graph nor seeds yield indicators', async () => {
        mockNl.mockResolvedValue(nlOk([{ name: 'no indicators here' }]));
        mockConfigured.mockReturnValue(true);

        const r = await graphFirstHunt({ question: 'empty' });
        expect(r.graph.indicators).toEqual([]);
        expect(r.siem.query).toBeUndefined();
        expect(mockSearch).not.toHaveBeenCalled();
    });
});
