/**
 * LLM-driven threat-actor enrichment.
 *
 * Threat actor records come from heterogeneous STIX feeds (MISP galaxy, OTX,
 * Mandiant, etc.) and frequently lack `sophistication`, `primaryMotivation`,
 * `resourceLevel`, `aliases`, etc. — those fields are optional in STIX and
 * not every feed populates them.
 *
 * This service takes an actor's name + description and asks Gemini
 * (`gemini-2.5-flash`, JSON mode) to extract the missing structured fields.
 * It only RETURNS fields that were null/empty on input — the caller is
 * responsible for the DB update so we never overwrite a curated value.
 */
import { callLLM } from './aiMiddleware/callLLM';
import { createLogger } from '../lib/logger';
import { z } from 'zod';

const log = createLogger('ActorEnrichment');

const SOPHISTICATION_VALUES = ['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic'] as const;
const RESOURCE_LEVEL_VALUES = ['individual', 'club', 'contest', 'team', 'organization', 'government'] as const;
const MOTIVATION_VALUES = [
    'accidental', 'coercion', 'dominance', 'ideology', 'notoriety',
    'organizational-gain', 'personal-gain', 'personal-satisfaction', 'revenge', 'unpredictable',
] as const;
// STIX confidence enum. Existing ingestion writes these strings, so the LLM
// path matches to keep the column consistent across sources.
const CONFIDENCE_VALUES = ['none', 'low', 'medium', 'high'] as const;

/**
 * LLMs reliably produce reasonable-but-not-exact STIX values. Map common
 * synonyms to canonical STIX enums so we don't reject a sensible response
 * just because the model said "moderate" instead of "intermediate".
 */
const SOPHISTICATION_ALIASES: Record<string, typeof SOPHISTICATION_VALUES[number]> = {
    low: 'minimal', moderate: 'intermediate', medium: 'intermediate', high: 'advanced',
    'highly-sophisticated': 'expert', sophisticated: 'expert', elite: 'expert',
    'apt-level': 'strategic', 'nation-state-level': 'strategic',
};

const MOTIVATION_ALIASES: Record<string, typeof MOTIVATION_VALUES[number]> = {
    'financial-gain': 'organizational-gain', financial: 'organizational-gain',
    money: 'organizational-gain', profit: 'organizational-gain',
    extortion: 'organizational-gain', ransom: 'organizational-gain',
    espionage: 'dominance', intelligence: 'dominance', surveillance: 'dominance',
    political: 'ideology', activism: 'ideology', hacktivism: 'ideology',
    fame: 'notoriety', recognition: 'notoriety',
    sabotage: 'dominance', disruption: 'dominance',
};

const RESOURCE_LEVEL_ALIASES: Record<string, typeof RESOURCE_LEVEL_VALUES[number]> = {
    state: 'government', 'nation-state': 'government', 'state-sponsored': 'government',
    company: 'organization', corporate: 'organization', enterprise: 'organization',
    group: 'team', collective: 'team', crew: 'team',
    person: 'individual', single: 'individual', solo: 'individual',
};

/**
 * Coerce a value into one of an allowed enum or its known synonyms.
 * Returns undefined if neither matches.
 */
function coerceEnum<E extends string>(
    raw: unknown, allowed: readonly E[], aliases: Record<string, E>,
): E | undefined {
    if (typeof raw !== 'string') return undefined;
    const norm = raw.toLowerCase().trim().replace(/_/g, '-');
    if ((allowed as readonly string[]).includes(norm)) return norm as E;
    if (norm in aliases) return aliases[norm];
    return undefined;
}

/**
 * Coerce a model's confidence response to the STIX enum.
 * Accepts:
 *   - "high" / "Medium" / "LOW" → enum value
 *   - 80, "80" (0-100 percentage) → "high" (≥75), "medium" (50-74), "low" (25-49), "none" (<25)
 *   - 0.9 (0-1 probability) → scaled then bucketed
 */
function coerceConfidence(raw: unknown): typeof CONFIDENCE_VALUES[number] | undefined {
    if (raw == null) return undefined;

    // Try string enum first (with synonym fallback).
    if (typeof raw === 'string') {
        const norm = raw.toLowerCase().trim();
        if ((CONFIDENCE_VALUES as readonly string[]).includes(norm)) {
            return norm as typeof CONFIDENCE_VALUES[number];
        }
        if (norm === 'very-high' || norm === 'critical') return 'high';
        if (norm === 'moderate' || norm === 'mid') return 'medium';
        if (norm === 'minimal' || norm === 'very-low') return 'low';
        // Fall through to number parse for "90" etc.
        const n = Number(norm);
        if (Number.isFinite(n)) return bucketFromNumber(n);
        return undefined;
    }

    if (typeof raw === 'number') return bucketFromNumber(raw);
    return undefined;
}

function bucketFromNumber(n: number): typeof CONFIDENCE_VALUES[number] {
    // Probability (0-1) → scale up.
    const pct = n <= 1 && n > 0 ? n * 100 : n;
    if (pct >= 75) return 'high';
    if (pct >= 50) return 'medium';
    if (pct >= 25) return 'low';
    return 'none';
}

/** Permissive schema — coerce synonyms, floats, and reject only nonsense. */
const EnrichmentSchema = z.object({
    sophistication: z.unknown().transform(v => coerceEnum(v, SOPHISTICATION_VALUES, SOPHISTICATION_ALIASES)).optional(),
    resourceLevel: z.unknown().transform(v => coerceEnum(v, RESOURCE_LEVEL_VALUES, RESOURCE_LEVEL_ALIASES)).optional(),
    primaryMotivation: z.unknown().transform(v => coerceEnum(v, MOTIVATION_VALUES, MOTIVATION_ALIASES)).optional(),
    aliases: z.array(z.string().min(1).max(80)).max(10).nullable().optional(),
    goals: z.array(z.string().min(1).max(200)).max(8).nullable().optional(),
    labels: z.array(z.string().min(1).max(80)).max(10).nullable().optional(),
    // STIX confidence enum: 'none' | 'low' | 'medium' | 'high'. Coerce any
    // integer/probability/synonym the LLM might emit into the enum so the
    // stored value is consistent with strings ingested from STIX feeds.
    confidence: z.unknown().transform(v => coerceConfidence(v)).optional(),
});

/**
 * Public enrichment shape — matches Drizzle's column types for direct .set().
 * `confidence` is a STIX string enum to match values written by feed ingestion.
 */
export interface ActorEnrichment {
    sophistication?: typeof SOPHISTICATION_VALUES[number];
    resourceLevel?: typeof RESOURCE_LEVEL_VALUES[number];
    primaryMotivation?: typeof MOTIVATION_VALUES[number];
    aliases?: string[];
    goals?: string[];
    labels?: string[];
    confidence?: typeof CONFIDENCE_VALUES[number];
}

/**
 * Input the caller hands us — typically a row straight from the
 * `threat_actors` table. Field names match the Drizzle column casing.
 */
export interface EnrichmentInput {
    id?: string;
    name: string;
    description: string | null | undefined;
    aliases?: string[] | null;
    sophistication?: string | null;
    resourceLevel?: string | null;
    primaryMotivation?: string | null;
    goals?: string[] | null;
    labels?: string[] | null;
    /** Stored as varchar(20) in threat_actors, hence string. */
    confidence?: string | null;
}

const SYSTEM_PROMPT = `You are a senior CTI analyst extracting STIX 2.1 metadata.

INPUT: a threat actor's name + free-text description (and optionally already-known fields).
OUTPUT: a single JSON object using EXACTLY these keys — no others, no echo of the input:

  sophistication       — string, one of: none, minimal, intermediate, advanced, expert, innovator, strategic
  resourceLevel        — string, one of: individual, club, contest, team, organization, government
  primaryMotivation    — string, one of: accidental, coercion, dominance, ideology, notoriety, organizational-gain, personal-gain, personal-satisfaction, revenge, unpredictable
  aliases              — array of strings (alternate published names — NOT nicknames)
  goals                — array of strings (short noun phrases, max 8)
  labels               — array of strings (STIX classifiers: "nation-state", "cybercriminal", "ransomware-operator", "hacktivist", "spy", "criminal-enterprise", …)
  confidence           — string, one of: none, low, medium, high (STIX enum — your confidence in the inferred sophistication)

EXAMPLE INPUT:
  THREAT ACTOR: APT41
  DESCRIPTION: APT41 is a Chinese state-sponsored espionage group that also conducts
  financially motivated operations. The group has been active since 2012 and is known
  by aliases including BARIUM, Winnti, Wicked Panda. They primarily target the gaming
  industry, healthcare, and high-tech companies, and use a custom toolset for stealthy
  long-term access.

EXAMPLE OUTPUT (return JSON in this exact shape, omitting any field you cannot infer):
{
  "sophistication": "expert",
  "resourceLevel": "government",
  "primaryMotivation": "dominance",
  "aliases": ["BARIUM", "Winnti", "Wicked Panda"],
  "goals": ["espionage", "intellectual-property-theft", "financial-gain"],
  "labels": ["nation-state", "spy", "cybercriminal"],
  "confidence": "high"
}

STRICT RULES:
  1. NEVER include "name" or "description" in your output — those are inputs, not outputs.
  2. Use enum values EXACTLY as listed; do NOT invent new strings.
  3. "primaryMotivation": financial crime = "organizational-gain". Espionage / state interest = "dominance".
  4. Don't fabricate aliases or goals. Use [] if uncertain.
  5. Return JSON only — no prose, no markdown fences, no commentary.
  6. Omit a field entirely (don't include the key) if you cannot infer it confidently.`;

/**
 * Build the user prompt from an actor's name + description.
 * Existing-but-incomplete fields are passed in so the LLM doesn't
 * contradict known truth (e.g. you already know resourceLevel=government,
 * we don't want the LLM to "guess" individual).
 */
function buildPrompt(actor: EnrichmentInput): string {
    const known: Record<string, unknown> = {};
    if (actor.sophistication) known.sophistication = actor.sophistication;
    if (actor.resourceLevel) known.resourceLevel = actor.resourceLevel;
    if (actor.primaryMotivation) known.primaryMotivation = actor.primaryMotivation;
    if (actor.aliases?.length) known.aliases = actor.aliases;

    return `THREAT ACTOR: ${actor.name}

DESCRIPTION:
${actor.description || '(no description provided)'}

ALREADY-KNOWN FIELDS (do not contradict):
${Object.keys(known).length ? JSON.stringify(known, null, 2) : '(none)'}

Return the enrichment JSON now. Remember:
- ONLY the keys defined in the system prompt (sophistication, resourceLevel, primaryMotivation, aliases, goals, labels, confidence)
- DO NOT include "name" or "description" — those are inputs
- Omit any field you cannot infer confidently`;
}

/**
 * Run a single actor through Gemini. Returns ONLY the fields that were null
 * or empty in the input — caller-safe; merging an existing populated field
 * is never attempted.
 *
 * Throws on LLM failure so the caller can decide whether to retry or skip.
 */
export async function enrichActor(actor: EnrichmentInput): Promise<ActorEnrichment> {
    if (!actor.description || actor.description.trim().length < 20) {
        // Too little signal to safely infer anything.
        log.info('Skipping actor — description too short for enrichment', { name: actor.name });
        return {};
    }

    const prompt = buildPrompt(actor);

    // Prefer OpenRouter when configured — its JSON mode produces stricter
    // schema-adherent output than Gemini's free flash model in our testing.
    // Fall through to Gemini (the existing aiMiddleware fallback handles
    // both directions). Override via ACTOR_ENRICHMENT_PROVIDER if needed.
    const preferred = (process.env.ACTOR_ENRICHMENT_PROVIDER as 'openrouter' | 'gemini' | 'ollama' | undefined)
        || (process.env.OPENROUTER_API_KEY ? 'openrouter' : 'gemini');
    const model = preferred === 'openrouter'
        ? (process.env.ACTOR_ENRICHMENT_MODEL || 'google/gemini-2.5-flash')
        : (process.env.ACTOR_ENRICHMENT_MODEL || 'gemini-2.5-flash');

    const response = await callLLM(prompt, {
        provider: preferred,
        model,
        systemPrompt: SYSTEM_PROMPT,
        jsonMode: true,
        temperature: 0.2,
        // Bigger budget so even chatty completions don't truncate mid-string.
        maxTokens: 1500,
    });

    let parsed: z.infer<typeof EnrichmentSchema>;
    try {
        // Trim any stray prose/fences in case the model adds them despite instructions.
        const cleaned = response.text
            .trim()
            .replace(/^```json\s*/i, '')
            .replace(/^```\s*/i, '')
            .replace(/```$/i, '')
            .trim();
        const raw = JSON.parse(cleaned);
        parsed = EnrichmentSchema.parse(raw);
    } catch (err) {
        // Log the FULL response (not just 200 chars) so we can diagnose echoes
        // / truncation without re-running. Logged at warn — not fatal.
        log.warn('Failed to parse LLM enrichment response', {
            name: actor.name,
            error: (err as Error).message,
            length: response.text.length,
            response: response.text,
        });
        return {};
    }

    // Filter — only include fields that were null/empty on input. Never
    // overwrite curated data, even if the LLM disagrees.
    const out: ActorEnrichment = {};
    if (!actor.sophistication && parsed.sophistication) out.sophistication = parsed.sophistication;
    if (!actor.resourceLevel && parsed.resourceLevel) out.resourceLevel = parsed.resourceLevel;
    if (!actor.primaryMotivation && parsed.primaryMotivation) out.primaryMotivation = parsed.primaryMotivation;
    if (!actor.aliases?.length && parsed.aliases?.length) out.aliases = parsed.aliases;
    if (!actor.goals?.length && parsed.goals?.length) out.goals = parsed.goals;
    if (!actor.labels?.length && parsed.labels?.length) out.labels = parsed.labels;
    // STIX enum: 'none' | 'low' | 'medium' | 'high'.
    if (!actor.confidence && parsed.confidence) out.confidence = parsed.confidence;

    log.info('Enriched actor', { name: actor.name, filled: Object.keys(out) });
    return out;
}
