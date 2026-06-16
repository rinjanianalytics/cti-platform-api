/**
 * syncGenericRelationships() tests.
 *
 * Regression guard for the 2026-06-16 gap: the full Neo4j sync only
 * re-hydrated USES edges (syncRelationships resolves STIX UUID→MITRE ID).
 * Every other graph edge — telco EXPLOITS_VIA/USES_INTERFACE, STIX SDO links —
 * only ever hydrated at row-INSERT time, so a graph rebuild silently dropped
 * them and Neo4j was not reconstructible from Postgres. syncGenericRelationships
 * is the second pass that fixes that. These tests assert it:
 *   - queries the NON-uses rows,
 *   - groups by (srcLabel, tgtLabel, edge) and emits the right MERGE,
 *   - skips rows whose entity types don't resolve to a Neo4j label,
 *   - returns the count of edges actually created.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { runMock, selectMock } = vi.hoisted(() => ({
    runMock: vi.fn(),
    selectMock: vi.fn(),
}));

vi.mock('@rinjani/db', () => ({
    db: { select: selectMock },
    // tagged-template passthrough — the WHERE arg is ignored by the mocked chain
    sql: (strings: TemplateStringsArray) => ({ _sql: strings.join('?') }),
}));

vi.mock('../services/neo4j/driver', () => ({
    getNeo4jDriver: () => ({ session: () => ({ run: runMock, close: () => undefined }) }),
    ensureNeo4jConstraints: vi.fn(),
}));

import { syncGenericRelationships } from '../services/neo4j/syncRelationships';

/** Make db.select(...).from(...).where(...) resolve to `rows`. */
function dbReturns(rows: unknown[]) {
    selectMock.mockReturnValue({ from: () => ({ where: () => Promise.resolve(rows) }) });
}

beforeEach(() => {
    vi.clearAllMocks();
    runMock.mockResolvedValue({
        summary: { counters: { updates: () => ({ relationshipsCreated: 2 }) } },
    });
});
afterEach(() => vi.resetAllMocks());

describe('syncGenericRelationships', () => {
    it('groups telco rows into one EXPLOITS_VIA MERGE and skips unknown-label rows', async () => {
        dbReturns([
            { sourceType: 'fraud-scheme', sourceId: 'sim-swap:port-out', relationshipType: 'exploits-via', targetType: 'signaling-interface', targetId: 'diameter:s6a', description: 'd1', confidence: 85 },
            { sourceType: 'fraud-scheme', sourceId: 'irsf:premium', relationshipType: 'exploits-via', targetType: 'signaling-interface', targetId: 'ss7:map', description: null, confidence: null },
            // unknown source type → must be skipped, NOT crash, NOT MERGE-d
            { sourceType: 'banana', sourceId: 'x', relationshipType: 'related-to', targetType: 'signaling-interface', targetId: 'y', description: null, confidence: null },
        ]);

        const created = await syncGenericRelationships();

        // Two telco rows share one (FraudScheme|SignalingInterface|EXPLOITS_VIA)
        // group → exactly one batched run(); banana skipped.
        expect(runMock).toHaveBeenCalledTimes(1);
        const [cypher, params] = runMock.mock.calls[0];
        expect(cypher).toContain('MATCH (src:FraudScheme)');
        expect(cypher).toContain('MATCH (tgt:SignalingInterface)');
        expect(cypher).toContain('MERGE (src)-[r:EXPLOITS_VIA]->(tgt)');
        expect((params as { batch: unknown[] }).batch).toHaveLength(2);
        const ids = (params as { batch: Array<{ srcId: string }> }).batch.map((b) => b.srcId);
        expect(ids).toEqual(['sim-swap:port-out', 'irsf:premium']);
        expect(ids).not.toContain('x');
        // returns edges actually created (summary counter), not rows attempted
        expect(created).toBe(2);
    });

    it('separate edge types become separate MERGE batches', async () => {
        dbReturns([
            { sourceType: 'fraud-scheme', sourceId: 'a', relationshipType: 'exploits-via', targetType: 'signaling-interface', targetId: 'b', description: null, confidence: null },
            { sourceType: 'fraud-scheme', sourceId: 'a', relationshipType: 'uses-interface', targetType: 'signaling-interface', targetId: 'b', description: null, confidence: null },
        ]);
        await syncGenericRelationships();
        expect(runMock).toHaveBeenCalledTimes(2);
        const edges = runMock.mock.calls.map(([c]) => (c as string).match(/MERGE \(src\)-\[r:(\w+)\]/)?.[1]);
        expect(edges.sort()).toEqual(['EXPLOITS_VIA', 'USES_INTERFACE']);
    });

    it('returns 0 and never opens a session when there are no non-uses rows', async () => {
        dbReturns([]);
        const created = await syncGenericRelationships();
        expect(created).toBe(0);
        expect(runMock).not.toHaveBeenCalled();
    });
});
