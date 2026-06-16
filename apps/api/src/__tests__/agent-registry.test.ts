/**
 * Agent tool registry tests (AA.1).
 *
 * Locks the "data, not code" boundary: runTool() is the single choke point the
 * AA.1 route and the AA.2 loop both go through, so the allowlist + arg
 * validation + write-tool refusal must hold here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { nlMock } = vi.hoisted(() => ({ nlMock: vi.fn() }));
vi.mock('../services/nlCypher', () => ({ nlToCypherQuery: nlMock }));

import { listTools, getTool, runTool, __testing } from '../services/agent/registry';

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

    it('refuses a write tool until the HITL gate exists (AA.3)', async () => {
        // Register a throwaway write tool to prove runTool gates it.
        __testing.TOOLS['test.write'] = {
            name: 'test.write', description: 'x', write: true,
            argsSchema: (await import('zod')).z.object({}),
            handler: async () => 'should not run',
        };
        await expect(runTool('test.write', {})).rejects.toThrow(/mutates state.*HITL/);
        delete __testing.TOOLS['test.write'];
    });
});
