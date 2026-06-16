/**
 * Agent routes (AA.1) — the agentic-analytics tool plane.
 *
 * AA.1 is the registry + a single-tool executor. NO LLM, NO loop yet — this is
 * the validated, bound-handler foundation the ReAct orchestrator (AA.2) will
 * call internally via runTool(). Exposing it as a route first lets us verify
 * each tool round-trips through the allowlist + arg validation in isolation
 * before the loop drives it.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { requireAuth, requireRole } from '../../middleware/auth';
import { listTools, getTool, runTool, commitTool } from '../../services/agent/registry';
import { runAgent } from '../../services/agent/orchestrator';
import { createLogger } from '../../lib/logger';

const router = new Hono();
const log = createLogger('Agent');

const AgentRunSchema = z.object({
    question: z.string().min(3).max(500),
    maxSteps: z.number().int().min(1).max(10).optional(),
});

const AgentCommitSchema = z.object({
    tool: z.string().min(1),
    args: z.record(z.string(), z.unknown()),
});

router.use('*', requireAuth);

// GET /agent/tools — the handler-backed registry (executable twin of the static
// /v1/mcp/tools manifest).
router.get('/agent/tools', (c) => {
    return c.json({ success: true, data: listTools() });
});

// POST /agent/tool/:name — execute ONE validated, allowlisted tool.
router.post('/agent/tool/:name', requireRole('admin', 'analyst'), async (c) => {
    const name = c.req.param('name');
    if (!name || !getTool(name)) {
        return c.json(
            { success: false, error: { code: 'UNKNOWN_TOOL', message: `unknown tool: ${name}` } },
            404,
        );
    }
    const args = await c.req.json().catch(() => ({}));
    try {
        const result = await runTool(name, args);
        return c.json({ success: true, data: { tool: name, result } });
    } catch (err) {
        // Bad args / write-tool refusal → 400 (caller's fault); surface the
        // validation detail so the eventual orchestrator can self-correct.
        const message = (err as Error).message;
        log.warn('agent tool call failed', { tool: name, error: message });
        return c.json({ success: false, error: { code: 'TOOL_ERROR', message } }, 400);
    }
});

// POST /agent/run — the ReAct loop (AA.2). The orchestrator chains read-only
// tool calls to answer a multi-step question. Runs synchronously (bounded
// maxSteps); async via aiAnalysisQueue + run persistence lands with AA.4 memory.
router.post('/agent/run', requireRole('admin', 'analyst'), async (c) => {
    const parsed = AgentRunSchema.safeParse(await c.req.json().catch(() => ({})));
    if (!parsed.success) {
        return c.json(
            { success: false, error: { code: 'BAD_REQUEST', message: parsed.error.issues.map((i) => i.message).join('; ') } },
            400,
        );
    }
    try {
        const result = await runAgent(parsed.data.question, { maxSteps: parsed.data.maxSteps });
        return c.json({ success: true, data: result });
    } catch (err) {
        const message = (err as Error).message;
        log.error('agent run failed', { error: message });
        return c.json({ success: false, error: { code: 'AGENT_ERROR', message } }, 500);
    }
});

// POST /agent/commit — the HUMAN-IN-THE-LOOP gate (AA.3). An analyst approves a
// write the agent PROPOSED (from a run's proposedActions) and it is executed
// here — the only path that runs a write tool's handler. commitTool refuses
// read-only tools + unknown tools + bad args, and stamps the committing user.
router.post('/agent/commit', requireRole('admin', 'analyst'), async (c) => {
    const parsed = AgentCommitSchema.safeParse(await c.req.json().catch(() => ({})));
    if (!parsed.success) {
        return c.json(
            { success: false, error: { code: 'BAD_REQUEST', message: parsed.error.issues.map((i) => i.message).join('; ') } },
            400,
        );
    }
    const userId = c.get('user')?.id || 'unknown';
    try {
        const result = await commitTool(parsed.data.tool, parsed.data.args, { userId });
        log.info('agent write committed', { tool: parsed.data.tool, by: userId });
        return c.json({ success: true, data: { tool: parsed.data.tool, committed: result } }, 201);
    } catch (err) {
        const message = (err as Error).message;
        log.warn('agent commit rejected', { tool: parsed.data.tool, error: message });
        return c.json({ success: false, error: { code: 'COMMIT_ERROR', message } }, 400);
    }
});

export default router;
