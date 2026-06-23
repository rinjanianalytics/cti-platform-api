/**
 * Intel TTP extraction — Phase 3 (LLM).
 *
 * Tier-1 regex was a dead end here: CTI RSS feeds (and even the article pages)
 * almost never cite ATT&CK technique IDs — TTPs are described in prose
 * ("spearphishing attachment", "PowerShell for execution"). So we use the LLM
 * (extractEntities → callLLM, Gemini/OpenRouter) to map prose → technique IDs +
 * actor names, then resolve against the catalogue/gazetteer and write fresh
 * actor→technique attributions to actor_ttp_changes via the actor_ttp_state
 * dedup baseline (a pair already known is a no-op). See RSS-EXTRACTION-DESIGN.md.
 *
 * Provenance + confidence ride in actor_ttp_changes.note. LLM-extracted T-codes
 * are still validated against the techniques catalogue, and actor names against
 * the threat_actors gazetteer — so a hallucinated id/actor can't get written.
 */

import { db, sql } from '@rinjani/db';
import { actorTtpChanges, actorTtpState } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('IntelTTP');

const MAX_REPORTS_PER_RUN = 30;   // one LLM call each — bound cost/latency; backlog clears over hourly runs.
const CONFIDENCE = 0.5;           // LLM prose→TTP — medium; provenance in note for review.
const TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

interface Gazetteer {
    techByMitre: Map<string, string>;   // 'T1059' → attack-pattern--…  (validates LLM technique ids)
    actorByTerm: Map<string, string>;   // lowercased name/alias → intrusion-set--…  (resolves LLM actor names)
}

async function buildGazetteer(): Promise<Gazetteer> {
    const techRows = await db.execute(sql`
        SELECT mitre_id, real_stix_id FROM techniques
        WHERE real_stix_id IS NOT NULL AND real_stix_id <> ''
    `) as unknown as Array<{ mitre_id: string; real_stix_id: string }>;
    const techByMitre = new Map<string, string>();
    for (const r of techRows) techByMitre.set(r.mitre_id.toUpperCase(), r.real_stix_id);

    const actorRows = await db.execute(sql`
        SELECT real_stix_id, name, aliases FROM threat_actors
        WHERE real_stix_id IS NOT NULL AND real_stix_id <> ''
    `) as unknown as Array<{ real_stix_id: string; name: string; aliases: string[] | null }>;
    const actorByTerm = new Map<string, string>();
    for (const a of actorRows) {
        for (const term of [a.name, ...(a.aliases ?? [])]) {
            const t = (term ?? '').trim().toLowerCase();
            // Skip very short/generic terms an LLM might echo loosely.
            if ((t.length >= 4 && /\d/.test(t)) || t.length >= 5) {
                if (!actorByTerm.has(t)) actorByTerm.set(t, a.real_stix_id);
            }
        }
    }
    return { techByMitre, actorByTerm };
}

interface LlmEntities { threatActors?: unknown; techniques?: unknown }

/** Dynamic import — the api-side LLM helper; this feed runs inside the api process. */
async function extractEntities(text: string): Promise<LlmEntities> {
    // @ts-ignore — api service outside the worker rootDir, resolved at runtime
    const { extractEntities: fn } = await import('../../../api/src/services/aiMiddleware/helpers');
    return fn(text, { temperature: 0.1, maxTokens: 1024 });
}

const asStrings = (v: unknown): string[] => Array.isArray(v) ? v.map((x) => String(x)) : [];

export type IntelTtpResult = { reportsProcessed: number; ttpsAdded: number; llmCalls: number };

export async function runIntelTtpExtraction(): Promise<IntelTtpResult> {
    const gz = await buildGazetteer();
    if (gz.techByMitre.size === 0) {
        log.warn('Technique gazetteer empty (MITRE not synced?) — skipping extraction');
        return { reportsProcessed: 0, ttpsAdded: 0, llmCalls: 0 };
    }

    const stateRows = await db.execute(sql`SELECT actor_id, technique_id FROM actor_ttp_state`) as unknown as Array<{ actor_id: string; technique_id: string }>;
    const seen = new Set(stateRows.map((r) => `${r.actor_id}::${r.technique_id}`));

    const reports = await db.execute(sql`
        SELECT id, source, url, title, summary, published_at FROM intel_reports
        WHERE extraction_status = 'pending'
        ORDER BY published_at DESC NULLS LAST
        LIMIT ${MAX_REPORTS_PER_RUN}
    `) as unknown as Array<{ id: string; source: string; url: string; title: string; summary: string | null; published_at: Date | string | null }>;

    let ttpsAdded = 0;
    let llmCalls = 0;
    let processed = 0;

    for (const rep of reports) {
        const text = `${rep.title}\n\n${rep.summary ?? ''}`;
        let ents: LlmEntities;
        try {
            ents = await extractEntities(text);
            llmCalls++;
        } catch (err) {
            const msg = (err as Error).message;
            // No provider configured (no GEMINI/OPENROUTER key) — stop and leave
            // the rest pending so they extract once a key is set.
            if (/no llm provider/i.test(msg)) {
                log.warn('LLM unavailable — leaving reports pending', { msg });
                break;
            }
            // Transient per-report failure — mark error so it doesn't block the queue.
            await db.execute(sql`UPDATE intel_reports SET extraction_status='error', updated_at=now() WHERE id=${rep.id}`);
            continue;
        }
        processed++;

        // Techniques: LLM ids ∪ any verbatim T-codes, validated against the catalogue.
        const techIds = new Set<string>();
        for (const cand of [...asStrings(ents.techniques), ...(text.toUpperCase().match(TECH_RE) ?? [])]) {
            const id = String(cand).toUpperCase().match(TECH_RE)?.[0];
            if (id && gz.techByMitre.has(id)) techIds.add(id);
        }
        // Actors: LLM names resolved against the gazetteer (name/alias).
        const actorIds = new Set<string>();
        for (const name of asStrings(ents.threatActors)) {
            const id = gz.actorByTerm.get(name.trim().toLowerCase());
            if (id) actorIds.add(id);
        }

        const detectedAt = rep.published_at ? new Date(rep.published_at) : new Date();
        const newChanges: typeof actorTtpChanges.$inferInsert[] = [];
        const newState: typeof actorTtpState.$inferInsert[] = [];
        for (const actorId of actorIds) {
            for (const mid of techIds) {
                const tStix = gz.techByMitre.get(mid)!;
                const key = `${actorId}::${tStix}`;
                if (seen.has(key)) continue;
                seen.add(key);
                newChanges.push({
                    actorId, techniqueId: tStix, changeType: 'added', detectedAt,
                    note: JSON.stringify({ source: rep.source, url: rep.url, method: 'llm', confidence: CONFIDENCE, reportId: rep.id }),
                });
                newState.push({ actorId, techniqueId: tStix, observedAt: detectedAt });
            }
        }
        if (newChanges.length > 0) {
            await db.insert(actorTtpChanges).values(newChanges);
            await db.insert(actorTtpState).values(newState).onConflictDoNothing();
            ttpsAdded += newChanges.length;
        }

        await db.execute(sql`
            UPDATE intel_reports
            SET extraction_status = 'extracted',
                entities = ${JSON.stringify({ threatActors: asStrings(ents.threatActors), techniques: [...techIds] })}::jsonb,
                llm_provider = 'llm', updated_at = now()
            WHERE id = ${rep.id}
        `);
    }

    log.info('Intel TTP extraction done', { reportsProcessed: processed, ttpsAdded, llmCalls });
    return { reportsProcessed: processed, ttpsAdded, llmCalls };
}
