/**
 * Agentic-analytics ReAct loop (AA.2 — PLAN Phase 9, graph-first hunt).
 *
 * A bounded loop over callLLM(jsonMode): the model emits ONE structured action
 * per turn — either a tool call {tool,args} or a {final} answer. We validate
 * and execute the action through the AA.1 registry choke point (runTool), feed
 * the observation back, and repeat until the model finishes or the step budget
 * is exhausted. This is the NL→Cypher seam (emit-validate-execute) generalized
 * to N tools and iterated.
 *
 * Invariants (the PLAN plane rules):
 *   - The model never emits imperative code — only a tool NAME + structured
 *     args that runTool() validates against a closed allowlist + zod schema.
 *   - Bounded steps (the #137 no-runaway-loop lesson) + repeat detection.
 *   - All v1 tools are read-only; write tools stay refused until AA.3's HITL gate.
 *   - No native provider tool-calling — pure JSON over callLLM(jsonMode), so it
 *     is provider-agnostic and reuses the output plane hardened in #137–#141.
 */

import { callLLM } from '../aiMiddleware';
import { listTools, runTool } from './registry';
import { createLogger } from '../../lib/logger';

const log = createLogger('AgentLoop');

const MAX_STEPS_DEFAULT = 6;
const MAX_STEPS_CEILING = 10;
const OBSERVATION_CAP = 2000; // chars of tool output fed back into context

export interface AgentStep {
    thought?: string;
    tool?: string;
    args?: unknown;
    /** Truncated JSON tool result, or an error/control string. */
    observation: string;
}

export interface AgentRunResult {
    question: string;
    /** The final analytic answer, grounded in the tool observations. */
    answer: string;
    /** Full trace — provenance for HITL (AA.3) and agent memory (AA.4). */
    steps: AgentStep[];
    stopReason: 'final' | 'max-steps' | 'no-answer';
    meta: { model: string; provider: string; steps: number };
}

interface Action {
    thought?: string;
    tool?: string;
    args?: unknown;
    final?: string;
}

function buildSystemPrompt(maxSteps: number): string {
    const catalog = listTools().map((t) => `  - ${t.name}: ${t.description}`).join('\n');
    return `You are a cyber-threat-intelligence analysis agent. Answer the user's question by calling READ-ONLY tools over the threat graph, ONE at a time, then giving a final analytic answer grounded in the tool results.

Available tools:
${catalog}

Protocol — reply with EXACTLY ONE JSON object per turn and NOTHING else:
  Call a tool:  {"thought":"<brief reasoning>","tool":"<tool name>","args":{ ... }}
  Finish:       {"thought":"<brief reasoning>","final":"<your analytic answer>"}

Rules:
  - ONE tool per turn. Read the OBSERVATION, then decide the next step.
  - graph.nlQuery answers English questions about the graph and returns records.
  - Base the final answer ONLY on observations — never invent data. If the graph
    has no data for part of the question, say so explicitly.
  - Finish as soon as you can answer. Budget: at most ${maxSteps} tool calls.`;
}

/**
 * Pull the single JSON action out of the model reply — same robustness posture
 * as nlCypher.extractCypher: tolerate a fence or stray prose around the object.
 */
function parseAction(raw: string): Action | null {
    const s = raw.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
    try {
        const obj = JSON.parse(s);
        if (obj && typeof obj === 'object') return obj as Action;
    } catch {
        const m = s.match(/\{[\s\S]*\}/);
        if (m) {
            try {
                return JSON.parse(m[0]) as Action;
            } catch {
                /* fall through */
            }
        }
    }
    return null;
}

/** Run the agent loop to completion (synchronous from the caller's view). */
export async function runAgent(
    question: string,
    opts: { maxSteps?: number } = {},
): Promise<AgentRunResult> {
    const maxSteps = Math.min(MAX_STEPS_CEILING, Math.max(1, opts.maxSteps ?? MAX_STEPS_DEFAULT));
    const system = buildSystemPrompt(maxSteps);
    const steps: AgentStep[] = [];
    const transcript: string[] = [`QUESTION: ${question}`];
    const seen = new Set<string>();
    let meta = { model: '', provider: '' };

    for (let i = 0; i < maxSteps; i++) {
        const llm = await callLLM(transcript.join('\n\n'), {
            systemPrompt: system,
            temperature: 0.1,
            maxTokens: 700,
            jsonMode: true,
        });
        meta = { model: llm.model, provider: llm.provider };
        const action = parseAction(llm.text);

        if (!action) {
            transcript.push('OBSERVATION: your last reply was not a single JSON object. Reply with one JSON object only.');
            steps.push({ observation: 'control: unparseable model output' });
            continue;
        }
        if (typeof action.final === 'string' && action.final.trim()) {
            log.info('agent finished', { steps: steps.length, provider: meta.provider });
            return { question, answer: action.final.trim(), steps, stopReason: 'final', meta: { ...meta, steps: steps.length } };
        }
        if (!action.tool) {
            transcript.push('OBSERVATION: you must call a tool or provide a non-empty "final".');
            steps.push({ thought: action.thought, observation: 'control: no tool and no final' });
            continue;
        }

        // Repeat detection — same tool+args twice means the loop is thrashing;
        // nudge it to vary or finish rather than burn the budget.
        const sig = `${action.tool}:${JSON.stringify(action.args ?? {})}`;
        if (seen.has(sig)) {
            transcript.push(`OBSERVATION: you already ran ${action.tool} with those args. Use the earlier result, try a different call, or finish.`);
            steps.push({ thought: action.thought, tool: action.tool, args: action.args, observation: 'control: duplicate call skipped' });
            continue;
        }
        seen.add(sig);

        let observation: string;
        try {
            const result = await runTool(action.tool, action.args ?? {});
            observation = JSON.stringify(result).slice(0, OBSERVATION_CAP);
        } catch (err) {
            // Tool/validation errors are fed back so the model can self-correct
            // (unknown tool, bad args, write-tool refusal) — not thrown.
            observation = `tool error: ${(err as Error).message}`;
        }
        steps.push({ thought: action.thought, tool: action.tool, args: action.args, observation });
        transcript.push(`ACTION: ${JSON.stringify({ tool: action.tool, args: action.args })}\nOBSERVATION: ${observation}`);
    }

    // Budget exhausted — ask for a final synthesis from what was gathered.
    const llm = await callLLM(
        `${transcript.join('\n\n')}\n\nYou are out of tool calls. Give your final answer now as {"final":"..."} based only on the observations above.`,
        { systemPrompt: system, temperature: 0.1, maxTokens: 700, jsonMode: true },
    );
    meta = { model: llm.model, provider: llm.provider };
    const action = parseAction(llm.text);
    if (action && typeof action.final === 'string' && action.final.trim()) {
        return { question, answer: action.final.trim(), steps, stopReason: 'max-steps', meta: { ...meta, steps: steps.length } };
    }
    return {
        question,
        answer: 'Inconclusive — the agent reached its step budget without a definitive answer.',
        steps,
        stopReason: 'no-answer',
        meta: { ...meta, steps: steps.length },
    };
}

export const __testing = { parseAction, buildSystemPrompt };
