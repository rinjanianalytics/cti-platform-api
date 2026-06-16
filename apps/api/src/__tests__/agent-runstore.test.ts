/**
 * Agent run persistence tests (AA.4).
 *
 * The store is the agent's memory. Key guarantees: a run is persisted with its
 * full trace + proposed actions; persistence NEVER throws into the request (a
 * computed answer must not be lost to a DB hiccup); reads cap their limit.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { dbMock } = vi.hoisted(() => ({ dbMock: { insert: vi.fn(), select: vi.fn() } }));
vi.mock('@rinjani/db', () => ({
    db: dbMock,
    eq: (...a: unknown[]) => ({ _eq: a }),
    desc: (x: unknown) => ({ _desc: x }),
}));
vi.mock('@rinjani/db/schema', () => ({ agentRuns: { id: 'id', createdAt: 'created_at' } }));

import { saveRun, saveFailedRun, getRun, listRuns } from '../services/agent/runStore';

const RESULT = {
    question: 'which schemes exploit Diameter?',
    answer: 'SIM-swap (port-out) does.',
    steps: [{ tool: 'graph.nlQuery', args: { question: 'x' }, observation: '{"records":[...]}' }],
    proposedActions: [{ tool: 'hypo.proposeEvidence', args: { hypothesisId: 'h1' }, summary: 's' }],
    stopReason: 'final' as const,
    meta: { model: 'gemini-flash-latest', provider: 'gemini', steps: 1 },
};

beforeEach(() => vi.clearAllMocks());
afterEach(() => vi.resetAllMocks());

describe('saveRun', () => {
    it('persists the full result (trace + proposals + meta) and returns the id', async () => {
        const valuesMock = vi.fn((_v: Record<string, unknown>) => ({ returning: async () => [{ id: 'run-1' }] }));
        dbMock.insert.mockReturnValue({ values: valuesMock });

        const id = await saveRun(RESULT, 'analyst-7');

        expect(id).toBe('run-1');
        const persisted = valuesMock.mock.calls[0][0];
        expect(persisted.question).toBe(RESULT.question);
        expect(persisted.answer).toBe(RESULT.answer);
        expect(persisted.steps).toEqual(RESULT.steps);
        expect(persisted.proposedActions).toEqual(RESULT.proposedActions);
        expect(persisted.stopReason).toBe('final');
        expect(persisted.status).toBe('completed');
        expect(persisted.stepCount).toBe(1);
        expect(persisted.createdBy).toBe('analyst-7');
    });

    it('NEVER throws on a DB error — returns null so the answer is still served', async () => {
        dbMock.insert.mockImplementation(() => { throw new Error('db unavailable'); });
        await expect(saveRun(RESULT, 'u')).resolves.toBeNull();
    });
});

describe('saveFailedRun', () => {
    it('records a failed run with the error', async () => {
        const valuesMock = vi.fn((_v: Record<string, unknown>) => ({ returning: async () => [{ id: 'run-2' }] }));
        dbMock.insert.mockReturnValue({ values: valuesMock });

        const id = await saveFailedRun('bad question', 'All LLM providers failed', 'u');

        expect(id).toBe('run-2');
        const persisted = valuesMock.mock.calls[0][0];
        expect(persisted.status).toBe('failed');
        expect(persisted.stopReason).toBe('error');
        expect(persisted.error).toBe('All LLM providers failed');
    });
});

describe('getRun', () => {
    it('returns the row', async () => {
        dbMock.select.mockReturnValue({ from: () => ({ where: () => ({ limit: async () => [{ id: 'r1', question: 'q' }] }) }) });
        expect(await getRun('r1')).toEqual({ id: 'r1', question: 'q' });
    });
    it('returns null when not found', async () => {
        dbMock.select.mockReturnValue({ from: () => ({ where: () => ({ limit: async () => [] }) }) });
        expect(await getRun('missing')).toBeNull();
    });
});

describe('listRuns', () => {
    it('caps the limit at 100', async () => {
        const limitMock = vi.fn(async () => []);
        dbMock.select.mockReturnValue({ from: () => ({ orderBy: () => ({ limit: limitMock }) }) });
        await listRuns(9999);
        expect(limitMock).toHaveBeenCalledWith(100);
    });
    it('floors the limit at 1', async () => {
        const limitMock = vi.fn(async () => []);
        dbMock.select.mockReturnValue({ from: () => ({ orderBy: () => ({ limit: limitMock }) }) });
        await listRuns(0);
        expect(limitMock).toHaveBeenCalledWith(1);
    });
});
