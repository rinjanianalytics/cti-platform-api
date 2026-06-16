/**
 * Agent ReAct loop tests (AA.2).
 *
 * Drives runAgent() with a mocked LLM and a mocked registry so the LOOP logic
 * is tested in isolation: tool chaining, observation feedback, error
 * self-correction, repeat detection, the bounded-step synthesis, and parse
 * robustness. The "all providers fail would hang" discipline from #137 applies:
 * the loop is bounded, so a misbehaving model can never run forever.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { llmMock, runToolMock, getToolMock, validateArgsMock } = vi.hoisted(() => ({
    llmMock: vi.fn(),
    runToolMock: vi.fn(),
    getToolMock: vi.fn(),
    validateArgsMock: vi.fn(),
}));

vi.mock('../services/aiMiddleware', () => ({ callLLM: llmMock }));
vi.mock('../services/agent/registry', () => ({
    runTool: runToolMock,
    getTool: getToolMock,
    validateToolArgs: validateArgsMock,
    listTools: () => [{ name: 'graph.nlQuery', description: 'query the graph', write: false }],
}));

import { runAgent, __testing } from '../services/agent/orchestrator';

/** Queue a sequence of LLM replies; the last repeats if the loop over-runs. */
function llmReplies(...texts: string[]) {
    let i = 0;
    llmMock.mockImplementation(async () => ({
        text: texts[Math.min(i++, texts.length - 1)],
        provider: 'gemini',
        model: 'gemini-flash-latest',
    }));
}

beforeEach(() => {
    vi.clearAllMocks();
    // Default: every tool is a read tool (write:false) → runTool path.
    getToolMock.mockImplementation((name: string) => ({ name, write: false }));
});
afterEach(() => vi.resetAllMocks());

describe('runAgent — ReAct loop', () => {
    it('finishes immediately on a {final} reply, no tool call', async () => {
        llmReplies(JSON.stringify({ final: 'the answer' }));
        const r = await runAgent('q');
        expect(r.answer).toBe('the answer');
        expect(r.stopReason).toBe('final');
        expect(r.steps).toHaveLength(0);
        expect(runToolMock).not.toHaveBeenCalled();
    });

    it('chains a tool call then a final, feeding the observation back', async () => {
        runToolMock.mockResolvedValue({ records: [{ fraud_scheme: 'SIM-swap (port-out)' }] });
        llmReplies(
            JSON.stringify({ thought: 'query graph', tool: 'graph.nlQuery', args: { question: 'schemes exploiting Diameter?' } }),
            JSON.stringify({ final: 'SIM-swap (port-out) exploits the Diameter S6a interface.' }),
        );
        const r = await runAgent('which schemes exploit Diameter?');
        expect(runToolMock).toHaveBeenCalledWith('graph.nlQuery', { question: 'schemes exploiting Diameter?' });
        expect(r.steps).toHaveLength(1);
        expect(r.steps[0].tool).toBe('graph.nlQuery');
        expect(r.steps[0].observation).toContain('SIM-swap');
        expect(r.answer).toContain('SIM-swap');
        expect(r.stopReason).toBe('final');
    });

    it('feeds a tool error back instead of throwing (self-correct path)', async () => {
        runToolMock.mockRejectedValueOnce(new Error('unknown tool: os.exec'));
        llmReplies(
            JSON.stringify({ tool: 'os.exec', args: {} }),
            JSON.stringify({ final: 'recovered after the bad call' }),
        );
        const r = await runAgent('q');
        expect(r.steps[0].observation).toContain('tool error: unknown tool');
        expect(r.answer).toBe('recovered after the bad call');
    });

    it('detects a repeated tool+args and does not execute it twice', async () => {
        runToolMock.mockResolvedValue({ ok: 1 });
        llmReplies(
            JSON.stringify({ tool: 'graph.nlQuery', args: { question: 'x' } }),
            JSON.stringify({ tool: 'graph.nlQuery', args: { question: 'x' } }), // duplicate
            JSON.stringify({ final: 'done' }),
        );
        const r = await runAgent('q');
        expect(runToolMock).toHaveBeenCalledTimes(1);
        expect(r.steps[1].observation).toContain('duplicate');
        expect(r.answer).toBe('done');
    });

    it('handles an unparseable reply, then recovers', async () => {
        llmReplies('I cannot output JSON, sorry', JSON.stringify({ final: 'ok now' }));
        const r = await runAgent('q');
        expect(r.steps[0].observation).toContain('unparseable');
        expect(r.answer).toBe('ok now');
        expect(runToolMock).not.toHaveBeenCalled();
    });

    it('stops at maxSteps then asks for a synthesis (bounded — never runs forever)', async () => {
        runToolMock.mockResolvedValue({ ok: 1 });
        let call = 0;
        llmMock.mockImplementation(async () => {
            call++;
            const text = call <= 2
                ? JSON.stringify({ tool: 'graph.nlQuery', args: { question: `q${call}` } })
                : JSON.stringify({ final: 'synthesized from 2 steps' });
            return { text, provider: 'gemini', model: 'm' };
        });
        const r = await runAgent('q', { maxSteps: 2 });
        expect(r.stopReason).toBe('max-steps');
        expect(r.steps).toHaveLength(2);
        expect(r.answer).toBe('synthesized from 2 steps');
        expect(llmMock).toHaveBeenCalledTimes(3); // 2 loop turns + 1 synthesis
    });

    it('STAGES a write tool — proposes, never executes (the HITL invariant)', async () => {
        getToolMock.mockImplementation((name: string) => ({ name, write: name === 'hypo.proposeEvidence' }));
        validateArgsMock.mockReturnValue({
            tool: { write: true },
            args: { hypothesisId: 'h1', evidenceType: 'freeform', kind: 'supports', note: 'sim-swap exploits Diameter' },
        });
        llmReplies(
            JSON.stringify({ tool: 'hypo.proposeEvidence', args: { hypothesisId: 'h1', evidenceType: 'freeform', kind: 'supports', note: 'sim-swap exploits Diameter' } }),
            JSON.stringify({ final: 'proposed one evidence item for review' }),
        );
        const r = await runAgent('does sim-swap support hypothesis h1?');
        expect(runToolMock).not.toHaveBeenCalled();              // write NEVER executed mid-run
        expect(r.proposedActions).toHaveLength(1);
        expect(r.proposedActions[0].tool).toBe('hypo.proposeEvidence');
        expect(r.steps[0].observation).toContain('STAGED');
        expect(r.answer).toBe('proposed one evidence item for review');
    });

    it('truncates a large observation before feeding it back', async () => {
        runToolMock.mockResolvedValue({ blob: 'A'.repeat(5000) });
        llmReplies(
            JSON.stringify({ tool: 'graph.nlQuery', args: { question: 'big' } }),
            JSON.stringify({ final: 'ok' }),
        );
        const r = await runAgent('q');
        expect(r.steps[0].observation.length).toBeLessThanOrEqual(2000);
    });
});

describe('parseAction robustness (reuses the nlCypher extraction posture)', () => {
    const { parseAction } = __testing;
    it('parses a fenced JSON action', () => {
        expect(parseAction('```json\n{"final":"x"}\n```')).toEqual({ final: 'x' });
    });
    it('finds the JSON object amid prose', () => {
        expect(parseAction('Sure thing: {"tool":"t","args":{}} hope that helps')).toEqual({ tool: 't', args: {} });
    });
    it('returns null for non-JSON', () => {
        expect(parseAction('no json here at all')).toBeNull();
    });
});
