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
import { nlToCypherQuery } from '../nlCypher';
import { neighborhoodExpand } from '../neo4jGraph';
import { vectorSearch } from '../opensearch/vector';

export interface AgentTool<A = unknown> {
    name: string;
    /** One-line description the orchestrator's system prompt shows the LLM. */
    description: string;
    /** Zod schema — validates the LLM-supplied args before the handler runs. */
    argsSchema: z.ZodType<A>;
    /** The bound service call. */
    handler: (args: A) => Promise<unknown>;
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
        'Translate an English question into a read-only Cypher query over the threat graph and ' +
        'return matching records. Use for "which / what / how-many" questions about actors, malware, ' +
        'IOCs, campaigns, telco fraud schemes, signaling interfaces, etc.',
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
 * Validate args against the tool's schema and run it. Throws on an unknown
 * tool, a write tool (until AA.3's HITL gate), or invalid args. The single
 * choke point both the AA.1 route and the AA.2 loop go through — so the
 * allowlist + validation can never be bypassed.
 */
export async function runTool(name: string, rawArgs: unknown): Promise<unknown> {
    const tool = getTool(name);
    if (!tool) throw new Error(`unknown tool: ${name}`);
    if (tool.write) {
        throw new Error(`tool '${name}' mutates state — HITL gate not implemented yet (AA.3)`);
    }
    const parsed = tool.argsSchema.safeParse(rawArgs);
    if (!parsed.success) {
        const detail = parsed.error.issues
            .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
            .join('; ');
        throw new Error(`invalid args for '${name}': ${detail}`);
    }
    return tool.handler(parsed.data);
}

/** Exposed for tests. */
export const __testing = { TOOLS };
