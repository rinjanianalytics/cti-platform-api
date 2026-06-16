/**
 * Agent tool registry (AA.1).
 *
 * The closed allowlist of tools the agentic-analytics layer may invoke. This is
 * the "data, not code" boundary for the orchestrator: the LLM (AA.2) picks a
 * tool NAME + structured args; it can NEVER reach an unbound handler or emit
 * imperative code. Every tool is a thin binding over an already-shipped,
 * read-only service — we are not building new capabilities here, only making
 * the existing ones agent-callable.
 *
 * v1 binds graph.nlQuery (the hardened NL→Cypher path). More read-only tools
 * (graph.expand, rag.search, hypo.read) land with the ReAct loop in AA.2;
 * write tools (hypo.proposeEvidence) land behind the HITL gate in AA.3.
 */

import { z } from 'zod';
import { db, eq } from '@rinjani/db';
import { hypotheses, hypothesisEvidence } from '@rinjani/db/schema';
import { nlToCypherQuery } from '../nlCypher';
import { neighborhoodExpand } from '../neo4jGraph';
import { vectorSearch } from '../opensearch/vector';

/** Per-call context the route supplies to a handler (e.g. the committing user). */
export interface ToolContext {
    userId?: string;
}

export interface AgentTool<A = unknown> {
    name: string;
    /** One-line description the orchestrator's system prompt shows the LLM. */
    description: string;
    /** Zod schema — validates the LLM-supplied args before the handler runs. */
    argsSchema: z.ZodType<A>;
    /** The bound service call. ctx carries request info (e.g. committing user). */
    handler: (args: A, ctx?: ToolContext) => Promise<unknown>;
    /**
     * true = the tool mutates state and must be HITL-gated (AA.3). v1 has none;
     * runTool() refuses write tools until the gate exists, so a write tool
     * registered early can never silently auto-execute.
     */
    write?: boolean;
}

const TOOLS: Record<string, AgentTool> = {};

function register<A>(tool: AgentTool<A>): void {
    TOOLS[tool.name] = tool as unknown as AgentTool;
}

register({
    name: 'graph.nlQuery',
    description:
        'Answer a question about the threat graph. Pass a plain-ENGLISH question in the "question" ' +
        'arg (NOT Cypher — the tool writes the read-only Cypher for you) and it returns matching ' +
        'records. Use for "which / what / how-many" questions about actors, malware, IOCs, campaigns, ' +
        'telco fraud schemes, signaling interfaces, etc. Example args: {"question": "which actors use Emotet?"}.',
    argsSchema: z.object({
        question: z.string().min(3).max(500),
        limit: z.number().int().min(1).max(100).optional(),
    }),
    handler: (args) => nlToCypherQuery(args.question, { limit: args.limit }),
});

register({
    name: 'graph.expand',
    description:
        'Expand the neighborhood around a known graph node (by its id/name/value/stixId/cveId/mitreId) ' +
        'to N hops. Use to PIVOT from an entity surfaced by a prior tool call to its connections.',
    argsSchema: z.object({
        nodeId: z.string().min(1).max(256),
        depth: z.number().int().min(1).max(3).optional(),
        limit: z.number().int().min(1).max(100).optional(),
    }),
    handler: (args) => neighborhoodExpand(args.nodeId, args.depth, args.limit),
});

register({
    name: 'rag.search',
    description:
        'Semantic (vector) search over indexed CTI entities. Use to find entities/past analysis ' +
        'related to a concept when you do not have an exact name or graph anchor.',
    argsSchema: z.object({
        query: z.string().min(3).max(500),
        k: z.number().int().min(1).max(20).optional(),
        entityType: z.enum(['ioc', 'vulnerability', 'actor', 'malware', 'campaign']).optional(),
    }),
    handler: (args) => vectorSearch(args.query, args.k, args.entityType),
});

// ---- write tools (HITL-gated, AA.3) ---------------------------------------
// The orchestrator may PROPOSE these; it never executes them. A proposed write
// is staged in the run result; an analyst commits it via POST /v1/agent/commit,
// which runs commitTool() — the only path that actually invokes a write handler.

register({
    name: 'hypo.proposeEvidence',
    description:
        'Propose a new evidence item supporting or refuting a hypothesis. This is a WRITE: it is ' +
        'NOT applied during the run — it is staged for a human analyst to approve. Use when a tool ' +
        'observation materially supports/refutes an existing hypothesis. Needs the hypothesis id.',
    write: true,
    argsSchema: z.object({
        hypothesisId: z.string().uuid(),
        evidenceType: z.enum(['ioc', 'relationship', 'sighting', 'actor', 'malware', 'campaign', 'report', 'freeform']),
        kind: z.enum(['supports', 'refutes']),
        note: z.string().min(1).max(2000),
        entityId: z.string().max(255).optional(),
        weight: z.number().int().min(0).max(100).optional(),
    }),
    handler: async (args, ctx) => {
        // Executed ONLY via commitTool() (the HITL gate), never during a run.
        const [parent] = await db
            .select({ id: hypotheses.id, status: hypotheses.status })
            .from(hypotheses)
            .where(eq(hypotheses.id, args.hypothesisId))
            .limit(1);
        if (!parent) throw new Error(`hypothesis not found: ${args.hypothesisId}`);
        if (parent.status !== 'active') {
            throw new Error(`hypothesis is ${parent.status}; reopen it before adding evidence`);
        }
        const [row] = await db
            .insert(hypothesisEvidence)
            .values({
                hypothesisId: args.hypothesisId,
                evidenceType: args.evidenceType,
                entityId: args.entityId ?? null,
                kind: args.kind,
                weight: args.weight ?? 50,
                note: args.note,
                createdBy: ctx?.userId ?? 'agent',
            })
            .returning();
        return row;
    },
});

export function getTool(name: string): AgentTool | undefined {
    return TOOLS[name];
}

/** The handler-backed catalog — the executable twin of the static /v1/mcp/tools manifest. */
export function listTools(): Array<{ name: string; description: string; write: boolean }> {
    return Object.values(TOOLS).map((t) => ({
        name: t.name,
        description: t.description,
        write: !!t.write,
    }));
}

/**
 * Resolve + validate a tool call WITHOUT executing it. The shared front half of
 * both runTool (reads) and commitTool (HITL writes), and what the orchestrator
 * uses to stage a well-formed write proposal. Throws on unknown tool / bad args.
 */
export function validateToolArgs(name: string, rawArgs: unknown): { tool: AgentTool; args: unknown } {
    const tool = getTool(name);
    if (!tool) throw new Error(`unknown tool: ${name}`);
    const parsed = tool.argsSchema.safeParse(rawArgs);
    if (!parsed.success) {
        const detail = parsed.error.issues
            .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
            .join('; ');
        throw new Error(`invalid args for '${name}': ${detail}`);
    }
    return { tool, args: parsed.data };
}

/**
 * Validate + run a READ-ONLY tool. Refuses write tools — those must go through
 * the HITL gate (commitTool). The choke point the AA.1 route and the AA.2 loop
 * use, so the allowlist + validation + read-only rule can never be bypassed.
 */
export async function runTool(name: string, rawArgs: unknown): Promise<unknown> {
    const { tool, args } = validateToolArgs(name, rawArgs);
    if (tool.write) {
        throw new Error(`tool '${name}' is a write tool — it must be committed via the HITL gate, not run directly`);
    }
    return tool.handler(args);
}

/**
 * Validate + EXECUTE a write tool — the human-in-the-loop gate. Only reached by
 * POST /v1/agent/commit after an analyst approves a staged proposal; the
 * orchestrator never calls this. Refuses non-write tools (reads go via runTool).
 */
export async function commitTool(name: string, rawArgs: unknown, ctx?: ToolContext): Promise<unknown> {
    const { tool, args } = validateToolArgs(name, rawArgs);
    if (!tool.write) {
        throw new Error(`tool '${name}' is read-only — use the run path, not the commit gate`);
    }
    return tool.handler(args, ctx);
}

/** Exposed for tests. */
export const __testing = { TOOLS };
