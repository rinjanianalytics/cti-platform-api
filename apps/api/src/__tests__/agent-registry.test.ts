/**
 * Agent tool registry tests (AA.1).
 *
 * Locks the "data, not code" boundary: runTool() is the single choke point the
 * AA.1 route and the AA.2 loop both go through, so the allowlist + arg
 * validation + write-tool refusal must hold here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { nlMock, dbMock } = vi.hoisted(() => ({ nlMock: vi.fn(), dbMock: { select: vi.fn(), insert: vi.fn() } }));
vi.mock('../services/nlCypher', () => ({ nlToCypherQuery: nlMock }));
vi.mock('@rinjani/db', () => ({ db: dbMock, eq: (...args: unknown[]) => ({ _eq: args }) }));

import { listTools, getTool, runTool, commitTool, validateToolArgs, __testing } from '../services/agent/registry';

const VALID_UUID = '00000000-0000-0000-0000-000000000001';

beforeEach(() => {
    vi.clearAllMocks();
    nlMock.mockResolvedValue({ question: 'q', cypher: 'MATCH (n) RETURN n LIMIT 25', records: [], success: true });
});
afterEach(() => vi.resetAllMocks());

describe('registry catalog', () => {
    it('lists graph.nlQuery as a read-only tool', () => {
        const tools = listTools();
        const nl = tools.find((t) => t.name === 'graph.nlQuery');
        expect(nl).toBeDefined();
        expect(nl!.write).toBe(false);
        expect(nl!.description.length).toBeGreaterThan(0);
    });

    it('getTool resolves a registered tool and returns undefined for others', () => {
        expect(getTool('graph.nlQuery')).toBeDefined();
        expect(getTool('graph.dropDatabase')).toBeUndefined();
    });
});

describe('runTool — allowlist + validation', () => {
    it('runs graph.nlQuery with valid args and returns the handler result', async () => {
        const out = await runTool('graph.nlQuery', { question: 'which actors use Emotet?' });
        expect(nlMock).toHaveBeenCalledWith('which actors use Emotet?', { limit: undefined });
        expect((out as { success: boolean }).success).toBe(true);
    });

    it('passes through an optional limit', async () => {
        await runTool('graph.nlQuery', { question: 'list malware', limit: 10 });
        expect(nlMock).toHaveBeenCalledWith('list malware', { limit: 10 });
    });

    it('rejects an unknown tool (never reaches a handler)', async () => {
        await expect(runTool('os.exec', { cmd: 'rm -rf /' })).rejects.toThrow(/unknown tool/);
        expect(nlMock).not.toHaveBeenCalled();
    });

    it('rejects invalid args with a descriptive error, before the handler runs', async () => {
        await expect(runTool('graph.nlQuery', { question: 'hi' })).rejects.toThrow(/invalid args.*question/i);
        await expect(runTool('graph.nlQuery', { limit: 5 })).rejects.toThrow(/invalid args/i);
        expect(nlMock).not.toHaveBeenCalled();
    });

});

describe('write-tool HITL gate (AA.3)', () => {
    it('lists hypo.proposeEvidence as a write tool', () => {
        const t = listTools().find((x) => x.name === 'hypo.proposeEvidence');
        expect(t?.write).toBe(true);
    });

    it('runTool REFUSES a write tool — reads only (cannot bypass the gate)', async () => {
        await expect(
            runTool('hypo.proposeEvidence', { hypothesisId: VALID_UUID, evidenceType: 'freeform', kind: 'supports', note: 'x' }),
        ).rejects.toThrow(/write tool.*committed via the HITL gate/);
        expect(dbMock.insert).not.toHaveBeenCalled();
    });

    it('commitTool REFUSES a read tool (commit gate is for writes)', async () => {
        await expect(commitTool('graph.nlQuery', { question: 'which actors?' })).rejects.toThrow(/read-only.*not the commit gate|read-only/i);
        expect(nlMock).not.toHaveBeenCalled();
    });

    it('commitTool executes a write tool and stamps the committing user', async () => {
        dbMock.select.mockReturnValue({ from: () => ({ where: () => ({ limit: async () => [{ id: VALID_UUID, status: 'active' }] }) }) });
        dbMock.insert.mockReturnValue({ values: vi.fn((v: Record<string, unknown>) => ({ returning: async () => [{ id: 'ev1', ...v }] })) });

        const out = await commitTool(
            'hypo.proposeEvidence',
            { hypothesisId: VALID_UUID, evidenceType: 'relationship', kind: 'supports', note: 'sim-swap exploits Diameter' },
            { userId: 'analyst-7' },
        ) as { createdBy: string; kind: string };

        expect(out.kind).toBe('supports');
        expect(out.createdBy).toBe('analyst-7'); // ctx.userId stamped, not 'agent'
    });

    it('commitTool rejects evidence on a non-active hypothesis', async () => {
        dbMock.select.mockReturnValue({ from: () => ({ where: () => ({ limit: async () => [{ id: VALID_UUID, status: 'confirmed' }] }) }) });
        await expect(
            commitTool('hypo.proposeEvidence', { hypothesisId: VALID_UUID, evidenceType: 'freeform', kind: 'refutes', note: 'x' }),
        ).rejects.toThrow(/confirmed.*reopen/);
    });

    it('validateToolArgs rejects unknown tool + bad args without executing', () => {
        expect(() => validateToolArgs('os.exec', {})).toThrow(/unknown tool/);
        expect(() => validateToolArgs('hypo.proposeEvidence', { hypothesisId: 'not-a-uuid', kind: 'supports', note: 'x', evidenceType: 'freeform' })).toThrow(/invalid args/);
    });
});
