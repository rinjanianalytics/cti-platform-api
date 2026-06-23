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
import { actorTtpChanges, actorTtpState, threatActors } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('IntelTTP');

const MAX_REPORTS_PER_RUN = 30;   // one LLM call each — bound cost/latency; backlog clears over hourly runs.
const CONFIDENCE = 0.5;           // LLM prose→TTP — medium; provenance in note for review.
const TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
const LLM_INPUT_CHARS = 16000;    // the attribution often lives in the article's back half (ATT&CK table); 8k cut it.
const MIN_BODY_CHARS = 800;       // below this the stored body is an RSS teaser — fetch the full article.
const FETCH_TIMEOUT_MS = 15000;
const UA = process.env.INTEL_NEWS_UA
    ?? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

/**
 * Fetch + flatten an article's full text. Several high-signal sources (The DFIR
 * Report especially) ship only a ~500-char teaser in RSS while the actual
 * actor→technique narrative — and the ATT&CK table — lives on the page. Strip
 * script/style first (their inline JS otherwise survives tag removal and
 * pollutes the prompt), prefer <article>, and bound the result.
 */
async function fetchArticleText(url: string): Promise<string> {
    const res = await fetch(url, { headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();
    const main = html.match(/<article[\s\S]*?<\/article>/i)?.[0] ?? html;
    return main
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]*>/g, ' ')
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#0?39;|&#x27;/gi, "'").replace(/&nbsp;/g, ' ')
        // eslint-disable-next-line no-control-regex
        .replace(/[\u0000-\u001f\u007f]/g, ' ')
        .replace(/\s+/g, ' ').trim()
        .slice(0, LLM_INPUT_CHARS);
}

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

interface Attribution { actor?: unknown; aliases?: unknown; techniques?: unknown }

/**
 * Purpose-built attribution extractor. The generic entity-lister returned actors
 * and techniques in separate buckets (and rarely any technique IDs), so no
 * (actor, technique) PAIR ever survived. Here we ask the LLM for the
 * relationship directly and to MAP PROSE → ATT&CK IDs — which is the whole point
 * (the reports describe TTPs in words, not codes). Dynamic import: the api-side
 * callLLM, resolved at runtime since this feed runs inside the api process.
 */
async function extractAttributions(title: string, body: string): Promise<Attribution[]> {
    // @ts-ignore — api service outside the worker rootDir, resolved at runtime
    const { callLLM } = await import('../../../api/src/services/aiMiddleware/callLLM');
    const prompt = `You are a CTI analyst. From the report, extract every attribution where a NAMED threat actor is described USING a technique, and map each technique to its MITRE ATT&CK ID (e.g. "spearphishing attachment" → T1566.001, "PowerShell" → T1059.001, "exploit public-facing app" → T1190). A threat actor is a tracked adversary GROUP / APT / intrusion-set / eCrime crew (e.g. "MuddyWater", "Lunar Spider", "KongTuke"). Do NOT treat tools, scanners, malware or ransomware families, botnets, loaders, vulnerabilities, products, vendors, or victims as actors. Only techniques the report says THIS actor used. For "aliases", list this group's OTHER well-known names across vendors — ALWAYS include its MITRE ATT&CK name if you know it (e.g. for "Cloaked Ursa"/"Midnight Blizzard" include "APT29"; for "Forest Blizzard"/"Fighting Ursa" include "APT28"); use [] if none. Return JSON only:
{"attributions":[{"actor":"<group name>","aliases":["<other names, incl MITRE name>"],"techniques":["T1566.001","T1059.001"]}]}
If no actor-technique attribution is present, return {"attributions":[]}.

TITLE: ${title}
REPORT:
${body.slice(0, LLM_INPUT_CHARS)}`;
    const res = await callLLM(prompt, { temperature: 0.1, maxTokens: 1024, jsonMode: true });
    try {
        const m = res.text.match(/\{[\s\S]*\}/);
        const obj = m ? JSON.parse(m[0]) : {};
        return Array.isArray(obj.attributions) ? obj.attributions : [];
    } catch {
        return [];
    }
}

const asStrings = (v: unknown): string[] => Array.isArray(v) ? v.map((x) => String(x)) : [];

// --- Emerging-actor resolution / creation ----------------------------------
// Most fresh CTI names emerging groups MITRE doesn't track (KongTuke, ExCone,
// Awaken Likho…). To record their TTPs we create a provenance-flagged
// threat_actors entry on demand — gated so tools/malware/junk don't leak in.
const CREATE_EMERGING = process.env.INTEL_TTP_CREATE_ACTORS !== '0';
// Words that signal a tool/malware/campaign-codename rather than an actor group.
const NON_ACTOR_RE = /\b(scanner|tool(kit)?|malware|ransomware|botnet|loader|stealer|infostealer|rat|backdoor|trojan|worm|framework|exploit|payload|dropper|miner|webshell|builder|cryptor|packer|wiper|keylogger|c2|cve|vulnerability)\b/i;
const GENERIC_ACTOR_RE = /^(the\s+)?(threat[- ]?actors?|attackers?|adversar(y|ies)|unknown|unidentified|unattributed|unnamed|various|multiple|n\/?a)$/i;

const slugify = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);

// MITRE usually tracks a group under the bare name; reports append " APT"/"Group".
function nameVariants(name: string): string[] {
    const base = name.trim();
    const stripped = base.replace(/\s+(apt|group|gang|team|crew|collective)$/i, '').trim();
    return stripped && stripped !== base ? [base, stripped] : [base];
}

// Gate for creating a NEW actor — mirror the gazetteer's indexing threshold so a
// created actor is always re-findable next run, and exclude obvious non-actors.
function isLikelyActor(name: string): boolean {
    const n = name.trim();
    if (!((n.length >= 4 && /\d/.test(n)) || n.length >= 5)) return false;
    if (!/[a-z]/i.test(n)) return false;
    if (NON_ACTOR_RE.test(n) || GENERIC_ACTOR_RE.test(n)) return false;
    return true;
}

const isLlmActorId = (id: string): boolean => id.startsWith('intrusion-set--llm-');

/**
 * Resolve an LLM actor (name + LLM-supplied aliases) to a real_stix_id.
 *  - Builds candidate terms from the name, suffix variants, and every alias.
 *  - PREFERS a MITRE entry over a synthetic emerging one — this is the vendor
 *    dedup: "Cloaked Ursa" with alias "APT29" folds into MITRE APT29 rather than
 *    spawning a duplicate actor.
 *  - Otherwise creates a flagged emerging entry, STORING the aliases so the same
 *    group resolves consistently under any of its vendor names next time.
 * Returns null when unresolved and not creatable (disabled / failed actor gate).
 */
async function resolveOrCreateActor(
    rawName: string, rawAliases: string[], gz: Gazetteer, ctx: { source: string; url: string; detectedAt: Date },
): Promise<{ id: string; created: boolean } | null> {
    const name = String(rawName ?? '').trim();
    if (!name) return null;
    const aliasNames = [...new Set(rawAliases.map((a) => String(a ?? '').trim()).filter(Boolean))].slice(0, 8);

    // Candidate terms: name + every alias, each with its suffix variant.
    const terms = [...new Set([name, ...aliasNames].flatMap(nameVariants).map((t) => t.toLowerCase()))];
    // Look them all up; a real MITRE id wins over a synthetic emerging one.
    let mitreId: string | undefined;
    let anyId: string | undefined;
    for (const t of terms) {
        const id = gz.actorByTerm.get(t);
        if (!id) continue;
        anyId ??= id;
        if (!isLlmActorId(id)) { mitreId = id; break; }
    }
    const resolvedId = mitreId ?? anyId;
    if (resolvedId) {
        for (const t of terms) if (!gz.actorByTerm.has(t)) gz.actorByTerm.set(t, resolvedId); // intra-run cache
        return { id: resolvedId, created: false };
    }

    if (!CREATE_EMERGING || !isLikelyActor(name)) return null;
    const id = `intrusion-set--llm-${slugify(name)}`;
    await db.insert(threatActors).values({
        stixId: id,
        realStixId: id,                          // changelog LEFT JOINs threat_actors.real_stix_id
        name,
        aliases: aliasNames,                     // so any vendor name folds back to this entry next run
        labels: ['llm-extracted', 'unverified'], // provenance — filterable/purgeable
        confidence: 'low',
        createdByRef: 'feed:intel-ttp',
        description: `Emerging actor auto-created from threat-intel narrative extraction (source: ${ctx.source}).`,
        externalReferences: [{ source_name: ctx.source, url: ctx.url }],
        firstSeen: ctx.detectedAt,
    }).onConflictDoNothing({ target: threatActors.stixId });
    for (const t of terms) gz.actorByTerm.set(t, id);
    return { id, created: true };
}

export type IntelTtpResult = { reportsProcessed: number; ttpsAdded: number; llmCalls: number; actorsCreated: number };

export async function runIntelTtpExtraction(): Promise<IntelTtpResult> {
    const gz = await buildGazetteer();
    if (gz.techByMitre.size === 0) {
        log.warn('Technique gazetteer empty (MITRE not synced?) — skipping extraction');
        return { reportsProcessed: 0, ttpsAdded: 0, llmCalls: 0, actorsCreated: 0 };
    }

    const stateRows = await db.execute(sql`SELECT actor_id, technique_id FROM actor_ttp_state`) as unknown as Array<{ actor_id: string; technique_id: string }>;
    const seen = new Set(stateRows.map((r) => `${r.actor_id}::${r.technique_id}`));

    // Spend the per-run LLM budget on the sources that actually carry actor→
    // technique narratives (DFIR intrusion analyses, vendor deep-dives) before
    // the thehackernews teaser firehose — otherwise recency alone fills every
    // run with short news items that yield nothing.
    const reports = await db.execute(sql`
        SELECT id, source, url, title, summary, published_at FROM intel_reports
        WHERE extraction_status = 'pending'
        ORDER BY (source IN ('dfir','talos','unit42','securelist','redcanary','mssecurity')) DESC,
                 published_at DESC NULLS LAST
        LIMIT ${MAX_REPORTS_PER_RUN}
    `) as unknown as Array<{ id: string; source: string; url: string; title: string; summary: string | null; published_at: Date | string | null }>;

    let ttpsAdded = 0;
    let llmCalls = 0;
    let processed = 0;
    const createdActors = new Set<string>();

    for (const rep of reports) {
        // Several high-signal feeds (DFIR especially) store only a ~500-char RSS
        // teaser. Pull the full article so the LLM sees the intrusion narrative +
        // ATT&CK table, not the intro. Best-effort: fall back to the teaser.
        let body = rep.summary ?? '';
        if (body.length < MIN_BODY_CHARS && rep.url) {
            try {
                const full = await fetchArticleText(rep.url);
                if (full.length > body.length) body = full;
            } catch (err) {
                log.debug?.('full-article fetch failed', { url: rep.url, msg: (err as Error).message });
            }
        }

        let attrs: Attribution[];
        try {
            attrs = await extractAttributions(rep.title, body);
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

        const detectedAt = rep.published_at ? new Date(rep.published_at) : new Date();
        const newChanges: typeof actorTtpChanges.$inferInsert[] = [];
        const newState: typeof actorTtpState.$inferInsert[] = [];
        const resolved: Array<{ actor: string; techniques: string[] }> = [];

        for (const a of attrs) {
            const actor = await resolveOrCreateActor(String(a.actor ?? ''), asStrings(a.aliases), gz, { source: rep.source, url: rep.url, detectedAt });
            if (!actor) continue; // unresolved + failed the actor gate (tool/junk) — skip
            const actorId = actor.id;
            if (actor.created) createdActors.add(actorId);
            const techMitre: string[] = [];
            for (const t of asStrings(a.techniques)) {
                const mid = String(t).toUpperCase().match(TECH_RE)?.[0];
                if (!mid || !gz.techByMitre.has(mid)) continue; // validate every id against the catalogue
                techMitre.push(mid);
                const tStix = gz.techByMitre.get(mid)!;
                const key = `${actorId}::${tStix}`;
                if (seen.has(key)) continue; // already known (MITRE or earlier report) — dedup
                seen.add(key);
                newChanges.push({
                    actorId, techniqueId: tStix, changeType: 'added', detectedAt,
                    note: JSON.stringify({ source: rep.source, url: rep.url, method: 'llm', confidence: CONFIDENCE, reportId: rep.id }),
                });
                newState.push({ actorId, techniqueId: tStix, observedAt: detectedAt });
            }
            if (techMitre.length) resolved.push({ actor: String(a.actor), techniques: techMitre });
        }

        if (newChanges.length > 0) {
            await db.insert(actorTtpChanges).values(newChanges);
            await db.insert(actorTtpState).values(newState).onConflictDoNothing();
            ttpsAdded += newChanges.length;
        }

        await db.execute(sql`
            UPDATE intel_reports
            SET extraction_status = 'extracted',
                entities = ${JSON.stringify({ attributions: resolved })}::jsonb,
                llm_provider = 'llm', updated_at = now()
            WHERE id = ${rep.id}
        `);
    }

    log.info('Intel TTP extraction done', { reportsProcessed: processed, ttpsAdded, llmCalls, actorsCreated: createdActors.size });
    return { reportsProcessed: processed, ttpsAdded, llmCalls, actorsCreated: createdActors.size };
}
