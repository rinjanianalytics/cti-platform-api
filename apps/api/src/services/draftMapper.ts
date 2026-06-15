/**
 * LLM Draft-Mapper — A5 of the declarative connector engine.
 *
 * Takes a sample payload + target entity + source name and returns a
 * proposed FeedManifest the engine can run. Constrained five ways:
 *
 *   1. Closed transform vocab. The prompt enumerates the 13 ops the engine
 *      knows; anything else fails zod at op-enum check.
 *   2. Mandatory dry-run. We runEngine(manifest, sample) before returning.
 *      Zero `ok` records → status: 'couldnt_map' with the engine errors.
 *   3. Entity gate. If the LLM emits a manifest for a different entity than
 *      the operator asked for, we reject it (prevents quiet drift).
 *   4. JSON-only output. The prompt forbids prose / fences; we strip and
 *      re-parse on a single failure as a safety net.
 *   5. Deterministic skeleton fallback. No provider reachable, parse fail,
 *      zod fail → we return a clearly-empty skeleton manifest with
 *      enabled=false + mapping={} so the operator UI can show "this is
 *      a starter, fill it in" rather than "the system pretended to map".
 *
 * Never returns a stub that LOOKS real — every couldn't-map path carries
 * an explicit `reason` and either the LLM's bad-but-validated manifest
 * (for dry-run failures, useful for editing) or the empty skeleton.
 */

import { FeedManifest, runEngine, type EntityKind } from '@rinjani/feed-engine';
import { callLLM } from './aiMiddleware/callLLM';
import type { LLMProvider } from './aiMiddleware/types';
import { createLogger } from '../lib/logger';

const log = createLogger('DraftMapper');

export interface DraftInput {
    sample: string;
    format: 'json' | 'csv' | 'text';
    entity: EntityKind;
    sourceName: string;
    provider?: LLMProvider;
    /**
     * Optional hint for JSON sources where the records array lives at a
     * non-obvious dot-path (e.g. "data.indicators[0].entries"). The engine
     * needs this to drive the extractor; the LLM is told to honour it.
     */
    recordsPathHint?: string;
}

export interface DraftDryRun {
    read: number;
    ok: number;
    failed: number;
    errors: Array<{ index: number; reason: string }>;
}

export interface DraftResult {
    status: 'ok' | 'couldnt_map';
    manifest: import('@rinjani/feed-engine').FeedManifest;
    dryRun?: DraftDryRun;
    reason?: string;
    llmMeta?: { provider: LLMProvider; model: string; latencyMs: number; tokensUsed?: number };
}

/** Maximum bytes of the sample payload we put into the prompt. */
const SAMPLE_MAX_BYTES = 8 * 1024;

// ============================================================================
// Skeleton fallback
// ============================================================================

/**
 * Empty starter manifest. Returned when the LLM can't or won't produce
 * something valid. The operator can pick it up in the UI builder (A6)
 * and fill in the mapping by hand.
 *
 * enabled: false is deliberate — a skeleton manifest must NEVER be
 * accidentally activated against a live feed.
 */
export function buildSkeleton(input: DraftInput): FeedManifest {
    const extract = input.format === 'csv'
        ? { csv: { delimiter: ',', hasHeader: true } }
        : input.format === 'text'
        ? { text: { commentPrefix: '#' } }
        : { recordsPath: input.recordsPathHint ?? 'data' };

    return {
        id: input.sourceName,
        name: input.sourceName,
        enabled: false,
        entity: input.entity,
        source: {
            url: 'https://example.com/REPLACE-ME',
            method: 'GET',
            headers: {},
            auth: { type: 'none' },
        },
        format: input.format,
        extract,
        mapping: {},
    } as FeedManifest;
}

// ============================================================================
// Prompt builder
// ============================================================================

const TRANSFORM_VOCAB_DOCS = `CLOSED TRANSFORM VOCAB — use exactly these op names (anything else is rejected):
- trim                                        → strip whitespace
- lower / upper                               → case change
- toNumber                                    → parse number; non-numeric → undefined
- toIso                                       → parse anything Date() can to ISO 8601
- coalesce                                    → turn "" into undefined (for required guard)
- default       arg: <fallback>               → use arg when value is null/undefined/""
- mapEnum       arg: { table, fallback? }     → exact-key lookup; fallback when miss
- regexExtract  arg: { pattern, group?: 0 }   → JS regex; returns matched group
- split         arg: { sep: "," }             → string → string[] (trimmed, empties dropped)
- stripPrefix   arg: "<prefix>"               → remove prefix if present
- bucketize     arg: { ranges: [{ min?, max?, value }], fallback? }
                                              → numeric ranges → enum; first-match-wins
- prepend       arg: <string[]>               → prepend literals to current array (wraps scalars)`;

const ENTITY_FIELDS: Record<EntityKind, { required: string; optional: string }> = {
    ioc: {
        required: `- type: one of "ip" | "domain" | "hostname" | "url" | "hash-md5" | "hash-sha1" | "hash-sha256" | "email"
- value: non-empty string
- source: non-empty string`,
        optional: `threatType (e.g. "c2","malware","phishing","ransomware"), confidence (int 0-100), severity ("low"|"medium"|"high"|"critical"), tags (string[]), firstSeen (ISO), lastSeen (ISO), pulseId`,
    },
    vulnerability: {
        required: `- cveId: matches /^CVE-\\d{4}-\\d{4,}$/i
- source: non-empty string`,
        optional: `description, cvssScore (0-10), cvssVector, severity ("none"|"low"|"medium"|"high"|"critical"), cweId, isExploited (bool), epssScore (0-1), epssPercentile (0-1), vendorProject, product, references (string[]), publishedDate (ISO), lastModified (ISO)`,
    },
    threat_actor: {
        required: `- name: non-empty string
- source: non-empty string`,
        optional: `description, aliases (string[]), sophistication, resourceLevel, primaryMotivation, secondaryMotivations (string[]), goals (string[]), labels (string[]), country, firstSeen (ISO), lastSeen (ISO)`,
    },
    malware: {
        required: `- name: non-empty string
- source: non-empty string`,
        optional: `description, aliases (string[]), malwareTypes (string[]), isFamily (bool), capabilities (string[]), labels (string[])`,
    },
    campaign: {
        required: `- name: non-empty string
- source: non-empty string`,
        optional: `description, aliases (string[]), objective, labels (string[]), firstSeen (ISO), lastSeen (ISO)`,
    },
    course_of_action: {
        required: `- name: non-empty string
- source: non-empty string`,
        optional: `description, actionType, actionDescription, labels (string[])`,
    },
    infrastructure: {
        required: `- name: non-empty string
- source: non-empty string`,
        optional: `description, infrastructureTypes (string[]), aliases (string[]), labels (string[]), firstSeen (ISO), lastSeen (ISO)`,
    },
    technique: {
        required: `- mitreId: matches /^T\\d{4}(\\.\\d{3})?$/ (e.g. T1059, T1059.001)
- name: non-empty string
- source: non-empty string`,
        optional: `description, detection, platforms (string[]), permissions (string[]), dataSources (string[]), isSubtechnique (bool), parentId, tacticIds (string[]), url`,
    },
    tool: {
        required: `- name: non-empty string
- source: non-empty string`,
        optional: `mitreId, aliases (string[]), description, type, platforms (string[]), techniqueIds (string[]), url`,
    },
};

export function buildPrompt(input: DraftInput): string {
    const truncated = input.sample.length > SAMPLE_MAX_BYTES
        ? input.sample.slice(0, SAMPLE_MAX_BYTES) + `\n... (truncated; original ${input.sample.length} bytes)`
        : input.sample;

    const fields = ENTITY_FIELDS[input.entity];
    const recordsPathHint = input.recordsPathHint
        ? `\nThe records array is at this dot-path inside the JSON: "${input.recordsPathHint}".`
        : '';

    return `You are a feed connector mapper. Given a sample threat-intelligence feed payload, propose a FeedManifest JSON the engine can run.

OUTPUT FORMAT
- Single JSON object only. No prose, no markdown code fences, no explanation.
- If you cannot map the sample to a manifest, output exactly: {"error": "<one-sentence reason>"}

MANIFEST SHAPE
{
  "id": "<source-key>",
  "name": "<human-readable name>",
  "enabled": true,
  "entity": "${input.entity}",
  "source": {
    "url": "<feed URL — placeholder is OK if the sample doesn't reveal it>",
    "method": "GET" | "POST",
    "headers": {},
    "body"?: <object for POST JSON body>,
    "auth": { "type": "none" | "bearer" | "apiKeyHeader", "header"?: "<HTTP-HEADER-NAME>", "secretEnv"?: "<ENV_VAR_NAME>" }
    //   header    = the HTTP header to send the secret in (apiKeyHeader only, e.g. "Auth-Key")
    //   secretEnv = the ENV VAR holding the secret value (e.g. "THREATFOX_AUTH_KEY") — NEVER the secret itself
  },
  "format": "${input.format}",
  "extract": {
    "recordsPath"?: "<dot.path>",                 // json
    "csv"?: { "delimiter": ",", "hasHeader": true },
    "text"?: { "commentPrefix": "#" }              // text: each non-blank/non-comment line → { line: "..." }
  },
  "mapping": { "<canonicalField>": <FieldMapping>, ... }
}

FIELDMAPPING SHAPE
{
  "from"?: "<dot-path-into-each-record>",  // mutually exclusive with "literal"
  "literal"?: <constant>,                  // for things like the "source" name
  "transforms": [{ "op": "<op>", "arg"?: <op-specific> }],
  "required": true | false
}

${TRANSFORM_VOCAB_DOCS}

TARGET ENTITY: ${input.entity}
Required canonical fields:
${fields.required}
Optional canonical fields you MAY emit if the data is present:
${fields.optional}

SOURCE NAME (use this verbatim as the "source" literal in the mapping): "${input.sourceName}"
${recordsPathHint}

SAMPLE PAYLOAD (${input.format}, first ${SAMPLE_MAX_BYTES} bytes):
${truncated}

Output the JSON manifest now.`;
}

// ============================================================================
// Main entry
// ============================================================================

export async function draftMapper(input: DraftInput): Promise<DraftResult> {
    const prompt = buildPrompt(input);

    let llmText: string;
    let llmMeta: DraftResult['llmMeta'];

    try {
        const response = await callLLM(prompt, {
            provider: input.provider,
            jsonMode: true,
            temperature: 0,
            maxTokens: 4096,
        });
        llmText = response.text;
        llmMeta = {
            provider: response.provider,
            model: response.model,
            latencyMs: response.latencyMs,
            tokensUsed: response.tokensUsed,
        };
    } catch (err) {
        log.warn('No LLM provider available; returning skeleton', { error: (err as Error).message });
        return {
            status: 'couldnt_map',
            manifest: buildSkeleton(input),
            reason: `LLM unavailable: ${(err as Error).message}`,
        };
    }

    // Best-effort JSON parse. Try raw first; on failure, strip markdown
    // fences (some models add them despite jsonMode) and retry once.
    let raw: unknown;
    try {
        raw = JSON.parse(llmText.trim());
    } catch {
        const stripped = llmText
            .replace(/^```(?:json)?\s*/i, '')
            .replace(/```\s*$/, '')
            .trim();
        try {
            raw = JSON.parse(stripped);
        } catch {
            return {
                status: 'couldnt_map',
                manifest: buildSkeleton(input),
                reason: 'LLM did not return valid JSON',
                llmMeta,
            };
        }
    }

    // The prompt allows an explicit error envelope when the LLM declines.
    if (raw && typeof raw === 'object' && 'error' in raw) {
        return {
            status: 'couldnt_map',
            manifest: buildSkeleton(input),
            reason: `LLM declined: ${String((raw as { error: unknown }).error)}`,
            llmMeta,
        };
    }

    const parsed = FeedManifest.safeParse(raw);
    if (!parsed.success) {
        const issues = parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`);
        return {
            status: 'couldnt_map',
            manifest: buildSkeleton(input),
            reason: `LLM output failed manifest schema: ${issues.join('; ')}`,
            llmMeta,
        };
    }

    // Entity gate — protects against quiet drift if the LLM ignored the brief.
    if (parsed.data.entity !== input.entity) {
        return {
            status: 'couldnt_map',
            manifest: buildSkeleton(input),
            reason: `LLM emitted entity '${parsed.data.entity}' but '${input.entity}' was requested`,
            llmMeta,
        };
    }

    // Mandatory dry-run against the sample. This is the gate PLAN.md A5
    // calls for — every suggestion is either a runnable manifest or an
    // explicit "couldn't map".
    const dryRunResult = runEngine(
        parsed.data as FeedManifest & { entity: typeof parsed.data.entity },
        input.sample,
    );
    const dryRun: DraftDryRun = {
        read: dryRunResult.stats.read,
        ok: dryRunResult.stats.ok,
        failed: dryRunResult.stats.failed,
        errors: dryRunResult.errors.slice(0, 5),
    };

    if (dryRun.ok === 0) {
        // Return the LLM's manifest (NOT the skeleton) so the operator can see
        // what it tried and edit it directly — it just doesn't actually parse
        // any records yet.
        return {
            status: 'couldnt_map',
            manifest: parsed.data,
            reason: 'engine dry-run produced zero records',
            dryRun,
            llmMeta,
        };
    }

    return {
        status: 'ok',
        manifest: parsed.data,
        dryRun,
        llmMeta,
    };
}
