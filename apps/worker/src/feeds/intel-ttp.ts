/**
 * Intel TTP extraction — Phase 2 of RSS + extraction (Tier 1, deterministic).
 *
 * Reads pending intel_reports and pulls fresh actor → technique TTPs out of the
 * narrative WITHOUT an LLM:
 *   - techniques: ATT&CK ids cited verbatim (T1059, T1059.001), validated
 *     against the `techniques` catalogue.
 *   - actors: matched against the `threat_actors` gazetteer (name + aliases).
 *   - co-occurrence in one report ⇒ "actor uses technique".
 *
 * Resolves both to their MITRE STIX ids (techniques.real_stix_id /
 * threat_actors.real_stix_id — the same id form mitreTtpDiff writes), then
 * appends to actor_ttp_changes via the actor_ttp_state dedup baseline: a pair
 * already in state is a no-op, a genuinely new attribution yields one FRESH
 * changelog row (detected_at = the article's publish date). That's what makes
 * the Latest TTP changelog live again. See docs/RSS-EXTRACTION-DESIGN.md.
 *
 * Provenance + confidence ride in actor_ttp_changes.note so every row is
 * traceable to a source URL.
 */

import { db, sql } from '@rinjani/db';
import { actorTtpChanges, actorTtpState, intelReports } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('IntelTTP');

const CONFIDENCE = 0.6;           // Tier-1 co-occurrence — medium-high, auto-written.
const MAX_REPORTS_PER_RUN = 300;
const TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

export interface Gazetteer {
    techByMitre: Map<string, string>;                          // 'T1059' → attack-pattern--…
    actors: Array<{ stixId: string; name: string; re: RegExp }>; // intrusion-set--… + a name/alias matcher
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Name/alias terms worth matching: drop short/generic tokens that false-match.
 * Keep digit-bearing short ids (FIN7, APT28) and anything ≥5 chars.
 */
function actorTerms(name: string, aliases: string[]): string[] {
    const raw = [name, ...(aliases ?? [])].map((t) => (t ?? '').trim().toLowerCase()).filter(Boolean);
    const keep = raw.filter((t) => (t.length >= 4 && /\d/.test(t)) || t.length >= 5);
    return [...new Set(keep)];
}

export async function buildGazetteer(): Promise<Gazetteer> {
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
    const actors: Gazetteer['actors'] = [];
    for (const a of actorRows) {
        const terms = actorTerms(a.name, a.aliases ?? []);
        if (terms.length === 0) continue;
        actors.push({
            stixId: a.real_stix_id,
            name: a.name,
            re: new RegExp(`\\b(?:${terms.map(esc).join('|')})\\b`, 'i'),
        });
    }
    return { techByMitre, actors };
}

/**
 * Pure: the catalogued techniques + known actors mentioned in `text`.
 * Actor matching is gated on a technique hit — an actor name alone (no TTP)
 * isn't an attribution and would just add noise.
 */
export function extractMatches(
    text: string,
    gz: Gazetteer,
): { techMitreIds: string[]; actors: Array<{ stixId: string; name: string }> } {
    const techMitreIds = [...new Set(text.toUpperCase().match(TECH_RE) ?? [])].filter((id) => gz.techByMitre.has(id));
    if (techMitreIds.length === 0) return { techMitreIds: [], actors: [] };
    const actors = gz.actors.filter((a) => a.re.test(text)).map((a) => ({ stixId: a.stixId, name: a.name }));
    return { techMitreIds, actors };
}

export interface IntelTtpResult { reportsProcessed: number; ttpsAdded: number }

export async function runIntelTtpExtraction(): Promise<IntelTtpResult> {
    const gz = await buildGazetteer();
    if (gz.techByMitre.size === 0) {
        log.warn('Technique gazetteer empty (MITRE not synced?) — skipping extraction');
        return { reportsProcessed: 0, ttpsAdded: 0 };
    }

    // Dedup baseline — every (actor, technique) we already know.
    const stateRows = await db.execute(sql`
        SELECT actor_id, technique_id FROM actor_ttp_state
    `) as unknown as Array<{ actor_id: string; technique_id: string }>;
    const seen = new Set(stateRows.map((r) => `${r.actor_id}::${r.technique_id}`));

    const reports = await db.execute(sql`
        SELECT id, source, url, title, summary, published_at FROM intel_reports
        WHERE extraction_status = 'pending'
        ORDER BY published_at DESC NULLS LAST
        LIMIT ${MAX_REPORTS_PER_RUN}
    `) as unknown as Array<{ id: string; source: string; url: string; title: string; summary: string | null; published_at: Date | string | null }>;

    let ttpsAdded = 0;
    for (const rep of reports) {
        const { techMitreIds, actors } = extractMatches(`${rep.title} ${rep.summary ?? ''}`, gz);
        const detectedAt = rep.published_at ? new Date(rep.published_at) : new Date();

        const newChanges: typeof actorTtpChanges.$inferInsert[] = [];
        const newState: typeof actorTtpState.$inferInsert[] = [];
        for (const actor of actors) {
            for (const mid of techMitreIds) {
                const tStix = gz.techByMitre.get(mid)!;
                const key = `${actor.stixId}::${tStix}`;
                if (seen.has(key)) continue;
                seen.add(key);
                newChanges.push({
                    actorId: actor.stixId,
                    techniqueId: tStix,
                    changeType: 'added',
                    detectedAt,
                    note: JSON.stringify({ source: rep.source, url: rep.url, method: 'regex', confidence: CONFIDENCE, reportId: rep.id }),
                });
                newState.push({ actorId: actor.stixId, techniqueId: tStix, observedAt: detectedAt });
            }
        }

        if (newChanges.length > 0) {
            await db.insert(actorTtpChanges).values(newChanges);
            await db.insert(actorTtpState).values(newState).onConflictDoNothing();
            ttpsAdded += newChanges.length;
        }

        const entities = { threatActors: actors.map((a) => a.name), techniques: techMitreIds };
        await db.execute(sql`
            UPDATE intel_reports
            SET extraction_status = 'extracted', entities = ${JSON.stringify(entities)}::jsonb, updated_at = now()
            WHERE id = ${rep.id}
        `);
    }

    log.info('Intel TTP extraction done', { reportsProcessed: reports.length, ttpsAdded });
    return { reportsProcessed: reports.length, ttpsAdded };
}
