/**
 * On-chain wallet store tests (AA.6.1).
 *
 * db-mocked CRUD: idempotent upsert on the natural key (ref_id), list filters
 * incl. the risk_tag JSONB containment, get, delete.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { dbMock } = vi.hoisted(() => ({
    dbMock: { insert: vi.fn(), select: vi.fn(), delete: vi.fn() },
}));
vi.mock('@rinjani/db', () => ({
    db: dbMock,
    eq: (col: unknown, val: unknown) => ({ _eq: [col, val] }),
    desc: (x: unknown) => ({ _desc: x }),
    ilike: (col: unknown, val: unknown) => ({ _ilike: [col, val] }),
    and: (...c: unknown[]) => ({ _and: c }),
    sql: (strings: TemplateStringsArray, ...v: unknown[]) => ({ _sql: strings.join('?'), v }),
}));
vi.mock('@rinjani/db/schema', () => ({
    wallets: { refId: 'ref_id', id: 'id', chain: 'chain', entityType: 'entity_type', entityLabel: 'entity_label', riskTags: 'risk_tags', createdAt: 'created_at' },
}));

import { upsertWallet, listWallets, getWallet, deleteWallet } from '../services/onchainStore';

beforeEach(() => vi.clearAllMocks());
afterEach(() => vi.resetAllMocks());

describe('upsertWallet', () => {
    it('upserts on ref_id (idempotent natural key) and returns the row', async () => {
        const onConflict = vi.fn((_opts: { target: unknown }) => ({ returning: async () => [{ id: 'w1', refId: 'eth:0xabc', confidence: 80 }] }));
        const values = vi.fn((_v: Record<string, unknown>) => ({ onConflictDoUpdate: onConflict }));
        dbMock.insert.mockReturnValue({ values });

        const row = await upsertWallet({ refId: 'eth:0xabc', address: '0xabc', chain: 'eth', confidence: 80 } as never);

        expect(row).toEqual({ id: 'w1', refId: 'eth:0xabc', confidence: 80 });
        // conflict target is the ref_id natural key — re-POST updates, not dup.
        expect(onConflict.mock.calls[0][0].target).toBe('ref_id');
        // confidence is carried through (attribution is confidence-weighted).
        expect((values.mock.calls[0][0] as { confidence: number }).confidence).toBe(80);
    });
});

describe('listWallets', () => {
    it('applies a risk_tag JSONB containment filter + caps the limit', async () => {
        const limit = vi.fn(async () => [{ id: 'w1' }]);
        const orderBy = vi.fn(() => ({ limit }));
        const where = vi.fn((_c: unknown) => ({ orderBy }));
        dbMock.select.mockReturnValue({ from: () => ({ where }) });

        const rows = await listWallets({ chain: 'eth', riskTag: 'mixer', limit: 9999 });

        expect(rows).toHaveLength(1);
        expect(limit).toHaveBeenCalledWith(500); // capped
        // a WHERE was built (chain eq + riskTag containment) — non-empty conds.
        expect(where).toHaveBeenCalled();
        expect((where.mock.calls[0][0] as { _and: unknown[] })._and).toHaveLength(2);
    });

    it('no filters → undefined WHERE', async () => {
        const limit = vi.fn(async () => []);
        const where = vi.fn(() => ({ orderBy: () => ({ limit }) }));
        dbMock.select.mockReturnValue({ from: () => ({ where }) });
        await listWallets();
        expect(where).toHaveBeenCalledWith(undefined);
    });
});

describe('getWallet / deleteWallet', () => {
    it('getWallet returns the row, or null when absent', async () => {
        dbMock.select.mockReturnValueOnce({ from: () => ({ where: () => ({ limit: async () => [{ id: 'w1' }] }) }) });
        expect(await getWallet('w1')).toEqual({ id: 'w1' });
        dbMock.select.mockReturnValueOnce({ from: () => ({ where: () => ({ limit: async () => [] }) }) });
        expect(await getWallet('missing')).toBeNull();
    });

    it('deleteWallet returns true when a row was removed, false otherwise', async () => {
        dbMock.delete.mockReturnValueOnce({ where: () => ({ returning: async () => [{ id: 'w1' }] }) });
        expect(await deleteWallet('w1')).toBe(true);
        dbMock.delete.mockReturnValueOnce({ where: () => ({ returning: async () => [] }) });
        expect(await deleteWallet('missing')).toBe(false);
    });
});
