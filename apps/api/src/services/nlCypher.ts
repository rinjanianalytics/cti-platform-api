/**
 * Natural-language → Cypher translator.
 *
 * Phase 3 #4. The existing /v1/graph/neo4j/cypher endpoint lets advanced
 * analysts run hand-written Cypher; this layer lets the rest of the team
 * ask questions in English and have the LLM emit the Cypher.
 *
 * Safety layers (defense in depth):
 *   1. The LLM is told to emit ONLY a SELECT-style MATCH statement,
 *      never a write operation.
 *   2. `isReadOnlyCypher()` rejects any string containing CREATE / MERGE /
 *      SET / DELETE / DETACH / REMOVE / DROP / CALL ... YIELD with side
 *      effects. Substring match, case-insensitive, with word boundaries
 *      so e.g. "DELETED_AT" property names don't false-positive.
 *   3. We pass the candidate through `executeCypher()` which runs the
 *      same blocklist a second time AND runs the query in a session
 *      opened with `defaultAccessMode: READ`. Neo4j itself will throw
 *      if the query attempts a write under READ mode.
 *
 * The translator does NOT cache; the dashboard side can add a cache
 * later if usage justifies it.
 */
import { callLLM } from './aiMiddleware';
import { executeCypher } from './neo4jGraph/graphAnalysis';
import { createLogger } from '../lib/logger';

const log = createLogger('NLCypher');

/**
 * The Neo4j schema documentation injected into the system prompt. Keep
 * this in sync with `apps/api/src/services/neo4j/syncRelationships.ts`
 * (NEO4J_LABEL_BY_ENTITY) — if you add a node label there, add it
 * here so the LLM can target it.
 */
const NEO4J_SCHEMA_DOC = `Node labels:
  - IOC        — properties: {value, type, severity, source, firstSeen, lastSeen, confidence}
  - Vulnerability — properties: {cveId, severity, cvssScore, publishedDate, isExploited, epssScore}
  - Actor      — properties: {mitreId, name, description, sophistication, primaryMotivation, aliases}
  - Malware    — properties: {mitreId, stixId, name, description}
  - Tool       — properties: {mitreId, name, description}
  - Technique  — properties: {mitreId, name, tactic, platform}
  - Campaign   — properties: {stixId, name, description, firstSeen, lastSeen, objective}
  - Mitigation — properties: {stixId, name, description}    // STIX course-of-action
  - Infrastructure — properties: {stixId, name, description, infrastructureTypes}
  // Telco vertical (B1) — keyed on refId (e.g. "ericsson:hss:core", "diameter:s6a")
  - NetworkElement     — properties: {refId, name, elementType, architectureSegment, vendor, description}  // HSS/UDM/AMF/MME/OCS/PCRF
  - SignalingInterface — properties: {refId, name, protocol, referencePoint, specRef}                       // SS7/Diameter/GTP
  - FraudScheme        — properties: {refId, name, schemeType, monetization, gsmaFsCategories, threeGppThreats}  // sim-swap/IRSF/wangiri
  // On-chain "follow the money" (Phase 8) — keyed on refId ("<chain>:<address>")
  - Wallet             — properties: {refId, address, chain, entityLabel, entityType, confidence, attributionSource, riskTags}  // attribution is confidence-weighted (0-100), never fact
  // MITRE FiGHT (5G/telco threats) + ATLAS (AI-system threats) — keyed on id
  - FightTechnique     — properties: {fightId, name, status, architectureSegment, tacticIds, platforms}  // 5G technique, e.g. FGT5004; architectureSegment RAN/Core/UE/OA&M
  - AtlasTechnique     — properties: {atlasId, name, maturity, tacticIds, attackReferenceId}              // AI/ML technique, e.g. AML.T0043

Edge types (rel-types in SCREAMING_SNAKE_CASE):
  - USES                  Actor → Malware|Tool|Technique
  - ATTRIBUTED_TO         IOC|Campaign → Actor
  - TARGETS               Actor|Malware → Sector|Region (string-encoded)
  - MITIGATES             Mitigation → Technique|Malware
  - INDICATES             IOC → Actor|Malware|Campaign
  - EXPLOITS              IOC|Malware → Vulnerability
  - COMMUNICATES_WITH     Malware → Infrastructure
  - BEACONS_TO            Malware → Infrastructure
  - CONTROLS              Actor → Infrastructure
  - DERIVED_FROM          IOC → IOC
  // Telco vertical (B1) edges
  - CONNECTS_TO           NetworkElement → NetworkElement (over a signaling interface)
  - USES_INTERFACE        FraudScheme → SignalingInterface
  - ENABLES_FRAUD         NetworkElement → FraudScheme    // misconfig/exposure enables the scheme
  - EXPLOITS_VIA          FraudScheme → SignalingInterface
  // On-chain follow-the-money edges (Phase 8)
  - CASHED_OUT_TO         FraudScheme → Wallet        // telco fraud → crypto cashout
  - SENT_FUNDS_TO         Wallet → Wallet             // fund flow
  - CONTROLS_WALLET       Actor → Wallet              // attribution (confidence-weighted)
  // MITRE FiGHT / ATLAS bridge edges (FW.1)
  - USES                  FraudScheme → FightTechnique // 5G fraud scheme employs a FiGHT technique
                          Actor → FightTechnique|AtlasTechnique
  - RELATED_TO            generic catch-all

Edge properties: {description, confidence (0-100), syncedAt}

Constraints:
  - Read-only queries ONLY. Write operations (CREATE, MERGE, DELETE, SET,
    REMOVE, DROP) will be rejected.
  - Always include a LIMIT clause (default 25) unless the question
    explicitly asks for a count.
  - Prefer descriptive RETURN aliases like \`actor.name AS actor\`.`;

const SYSTEM_PROMPT = `You translate cyber threat intelligence questions written in English
into a SINGLE Cypher query against the Neo4j graph described below.

${NEO4J_SCHEMA_DOC}

Output rules:
  - Reply with ONLY a JSON object of the exact form {"cypher": "<query>"}.
    Nothing else — no prose, no code fences, no explanation, no commentary
    inside or outside the JSON. Do NOT answer the question in words; your
    entire job is to put a Cypher query in the "cypher" field.
  - The "cypher" value is a SINGLE Cypher query starting with MATCH (or a
    // comment line).
  - Never emit CREATE, MERGE, SET, DELETE, DETACH, REMOVE, DROP, or
    CALL ... YIELD that has side effects.
  - Always include a LIMIT clause (use 25 unless the question implies
    otherwise) — except for COUNT/aggregation queries where a limit
    would be meaningless.
  - If the question is ambiguous, pick the most useful interpretation.
  - If the question can't be answered against this schema at all, return
    exactly {"cypher": "// unanswerable"}.

Example: {"cypher": "MATCH (a:Actor {name:'APT28'})-[:USES]->(m:Malware) RETURN m.name LIMIT 25"}`;

const WRITE_KEYWORD_RE = /\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP)\b/i;
const FORBIDDEN_PROCEDURE_RE = /\bCALL\s+(apoc\.create|apoc\.merge|apoc\.refactor|apoc\.periodic\.commit|db\.create|dbms\.security)\b/i;

/**
 * Static read-only check. Errs on the side of false-positives — we'd
 * rather refuse a legitimate read than accidentally accept a write.
 */
export function isReadOnlyCypher(query: string): { ok: true } | { ok: false; reason: string } {
    const trimmed = query.trim();
    if (!trimmed) return { ok: false, reason: 'empty query' };
    if (trimmed === '// unanswerable') return { ok: false, reason: 'unanswerable' };

    // Strip line comments before keyword scanning so a property like
    // // delete this later doesn't trigger.
    const stripped = trimmed.split('\n').map(l => l.replace(/\/\/.*$/, '')).join('\n');

    if (WRITE_KEYWORD_RE.test(stripped)) {
        return { ok: false, reason: 'write-operation keyword detected' };
    }
    if (FORBIDDEN_PROCEDURE_RE.test(stripped)) {
        return { ok: false, reason: 'mutation procedure detected' };
    }
    // Must contain MATCH (otherwise it's not even a read query)
    if (!/\bMATCH\b/i.test(stripped) && !/\bRETURN\b/i.test(stripped)) {
        return { ok: false, reason: 'no MATCH or RETURN clause' };
    }

    return { ok: true };
}

/**
 * Pull a Cypher query out of whatever the model actually returned.
 *
 * jsonMode ASKS for a clean `{"cypher": "<query>"}` object, but production
 * showed gemini-flash-latest ignoring it in two ways: (a) a prose preamble
 * before a fenced block ("Here is the JSON requested:\n```json{…}```"), and
 * (b) truncated JSON when the query ran past maxTokens. So extraction must be
 * robust to messy output rather than DEPEND on the model being clean. Tried in
 * order, most-structured first:
 *   1. A {"cypher": "<query>"} object found ANYWHERE in the text (tolerates a
 *      prose preamble and surrounding fences — the run-1 failure).
 *   2. The whole string as JSON, after stripping a leading/trailing fence
 *      (the clean jsonMode path).
 *   3. Salvage a raw query: from the first (OPTIONAL) MATCH to the end, with
 *      any trailing fence/prose trimmed (rescues truncated-JSON output that
 *      still contains a usable MATCH — the run-2 failure, and the ultimate
 *      net for a provider that ignores jsonMode entirely).
 *   4. Legacy plain-text: strip a "Cypher:" / "Query:" label.
 */
function extractCypher(raw: string): string {
    const s = raw.trim();

    // 1. A {"cypher": "..."} object anywhere — preamble/fence-tolerant. The
    //    captured group is a JSON string body (handles \" and \n escapes); we
    //    re-parse it as a JSON string literal to unescape.
    const objMatch = s.match(/"cypher"\s*:\s*"((?:[^"\\]|\\.)*)"/i);
    if (objMatch) {
        try {
            return (JSON.parse(`"${objMatch[1]}"`) as string).trim();
        } catch {
            /* malformed escape — fall through */
        }
    }

    // 2. Whole string as JSON, after stripping one leading/trailing fence.
    const unfenced = s.replace(/^```(?:json|cypher|sql)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
    try {
        const obj = JSON.parse(unfenced) as { cypher?: unknown };
        if (obj && typeof obj.cypher === 'string') return obj.cypher.trim();
    } catch {
        /* not JSON — fall through */
    }

    // 3. Salvage a raw query: grab from the first (OPTIONAL) MATCH onward,
    //    dropping any trailing code fence the model wrapped it in. This also
    //    rescues the // unanswerable sentinel when emitted bare.
    const matchIdx = unfenced.search(/(?:OPTIONAL\s+)?MATCH\b/i);
    if (matchIdx >= 0) {
        return unfenced.slice(matchIdx).replace(/```[\s\S]*$/, '').trim();
    }

    // 4. Legacy plain-text output. Strip a "Cypher:" / "Query:" label.
    return unfenced.replace(/^(?:cypher|query|here is the query)\s*:\s*/i, '').trim();
}

export interface NlCypherOptions {
    /** Cap on returned records. Default 25. */
    limit?: number;
    /** Force a particular LLM provider for this call. */
    provider?: 'gemini' | 'openrouter' | 'ollama';
}

export interface NlCypherResult {
    question: string;
    /** The Cypher query the LLM produced (post-extraction). */
    cypher: string;
    /** Records returned by the query. Empty when the query was rejected. */
    records: Record<string, unknown>[];
    /** True iff the safety check passed AND Neo4j returned records without error. */
    success: boolean;
    /** Populated when success=false. */
    error?: string;
    meta: {
        provider: string;
        model: string;
        tokensUsed?: number;
        llmLatencyMs: number;
        queryLatencyMs: number;
    };
}

/** End-to-end: NL question → Cypher → executed → records. */
export async function nlToCypherQuery(
    question: string,
    opts: NlCypherOptions = {},
): Promise<NlCypherResult> {
    const limit = Math.min(500, Math.max(1, opts.limit ?? 25));

    const t0 = Date.now();
    const llm = await callLLM(question, {
        systemPrompt: SYSTEM_PROMPT,
        temperature: 0.1, // we want Cypher determinism, not creative writing
        // 700, not 400: a verbose model can spend tokens on a preamble + fenced
        // JSON wrapper before the query, and a 400-cap truncated the JSON
        // mid-string in prod (invalid → unparseable). Headroom keeps the
        // {"cypher": "..."} object closed so extractCypher can read it.
        maxTokens: 700,
        provider: opts.provider,
        // Structured output — force a {"cypher": "..."} object so chatty models
        // (e.g. gemini-flash-latest) can't return a prose explanation instead of
        // a query. Honored by all three providers (responseMimeType / response_format
        // / format:json). extractCypher parses the field, with a plain-text fallback.
        jsonMode: true,
    });
    const llmLatencyMs = Date.now() - t0;

    const cypher = extractCypher(llm.text);
    const safety = isReadOnlyCypher(cypher);
    if (!safety.ok) {
        log.warn('nl→cypher rejected', { question, cypher, reason: safety.reason });
        return {
            question,
            cypher,
            records: [],
            success: false,
            error: `rejected: ${safety.reason}`,
            meta: {
                provider: llm.provider,
                model: llm.model,
                tokensUsed: llm.tokensUsed,
                llmLatencyMs,
                queryLatencyMs: 0,
            },
        };
    }

    const t1 = Date.now();
    try {
        const records = await executeCypher(cypher, {}, limit);
        return {
            question,
            cypher,
            records,
            success: true,
            meta: {
                provider: llm.provider,
                model: llm.model,
                tokensUsed: llm.tokensUsed,
                llmLatencyMs,
                queryLatencyMs: Date.now() - t1,
            },
        };
    } catch (err) {
        return {
            question,
            cypher,
            records: [],
            success: false,
            error: `execution failed: ${(err as Error).message}`,
            meta: {
                provider: llm.provider,
                model: llm.model,
                tokensUsed: llm.tokensUsed,
                llmLatencyMs,
                queryLatencyMs: Date.now() - t1,
            },
        };
    }
}

/** Exposed for unit tests so they can lock prompt + parse behaviour. */
export const __testing = { SYSTEM_PROMPT, extractCypher };
