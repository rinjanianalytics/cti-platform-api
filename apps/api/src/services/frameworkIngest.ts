/**
 * MITRE FiGHT (5G/telco) + ATLAS (AI) ingestion — FW.2.
 *
 * Productionizes the one-off Python seeders (apps/api/src/scripts/seed-*.py)
 * as a TypeScript service: download the upstream YAML, parse, and idempotent-
 * upsert into the fight_* / atlas_* tables. No Python, no container gymnastics —
 * runnable via POST /v1/ops/frameworks/sync and schedulable like any feed.
 *
 * Sources (override via env):
 *   ATLAS  github mitre-atlas/atlas-data  dist/ATLAS.yaml
 *   FiGHT  github mitre/FiGHT             fight.yaml
 */

import { parse as parseYaml } from 'yaml';
import { db, eq } from '@rinjani/db';
import {
    fightTactics, fightTechniques, fightMitigations, fightGroupTechniques,
    atlasTactics, atlasTechniques, atlasMitigations, atlasCaseStudies,
    threatActors,
} from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('FrameworkIngest');

const ATLAS_URL = process.env.MITRE_ATLAS_YAML_URL
    || 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml';
const FIGHT_URL = process.env.MITRE_FIGHT_YAML_URL
    || 'https://raw.githubusercontent.com/mitre/FiGHT/main/fight.yaml';

type Y = Record<string, unknown>;
const str = (v: unknown): string | null => (typeof v === 'string' ? v : v == null ? null : String(v));
const arr = (v: unknown): Y[] => (Array.isArray(v) ? (v as Y[]) : []);
const ids = (v: unknown): string[] =>
    arr(v).map((x) => (typeof x === 'object' && x ? str((x as Y).id) ?? '' : str(x) ?? '')).filter(Boolean);

async function fetchYaml(url: string): Promise<Y> {
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`framework source ${url} → ${res.status}`);
    return (parseYaml(await res.text()) ?? {}) as Y;
}

// ── ATLAS ───────────────────────────────────────────────────────────────────

export async function ingestAtlas(): Promise<{ tactics: number; techniques: number; mitigations: number; caseStudies: number }> {
    const data = await fetchYaml(ATLAS_URL);
    const matrix = arr(data.matrices)[0] ?? {};
    const tactics = arr(matrix.tactics);
    const techniques = arr(matrix.techniques);
    const mitigations = arr(matrix.mitigations);
    const caseStudies = arr(data['case-studies']);

    for (const t of tactics) {
        const ref = (t['ATT&CK-reference'] ?? {}) as Y;
        const atlasId = str(t.id) ?? '';
        const v = {
            atlasId, name: str(t.name) ?? '', description: str(t.description),
            attackReferenceId: str(ref.id), attackReferenceUrl: str(ref.url),
            url: `https://atlas.mitre.org/tactics/${atlasId}`,
        };
        await db.insert(atlasTactics).values(v).onConflictDoUpdate({ target: atlasTactics.atlasId, set: { ...v, updatedAt: new Date() } });
    }
    for (const t of techniques) {
        const ref = (t['ATT&CK-reference'] ?? {}) as Y;
        const atlasId = str(t.id) ?? '';
        const v = {
            atlasId, name: str(t.name) ?? '', description: str(t.description),
            maturity: str(t.maturity), subtechniqueOf: str(t['subtechnique-of']),
            tacticIds: ids(t.tactics), attackReferenceId: str(ref.id), attackReferenceUrl: str(ref.url),
            url: `https://atlas.mitre.org/techniques/${atlasId}`,
        };
        await db.insert(atlasTechniques).values(v).onConflictDoUpdate({ target: atlasTechniques.atlasId, set: { ...v, updatedAt: new Date() } });
    }
    for (const m of mitigations) {
        const atlasId = str(m.id) ?? '';
        const v = {
            atlasId, name: str(m.name) ?? '', description: str(m.description),
            techniqueIds: ids(m.techniques), mlLifecycle: arr(m['ml-lifecycle']).map(String) as unknown as string[],
            category: (Array.isArray(m.category) ? (m.category as string[]) : []),
            url: `https://atlas.mitre.org/mitigations/${atlasId}`,
        };
        await db.insert(atlasMitigations).values(v).onConflictDoUpdate({ target: atlasMitigations.atlasId, set: { ...v, updatedAt: new Date() } });
    }
    for (const cs of caseStudies) {
        const atlasId = str(cs.id) ?? '';
        const steps = arr(cs.procedure).map((s) => ({ tactic: str(s.tactic) ?? '', technique: str(s.technique) ?? '', description: str(s.description) ?? '' }));
        const refs = arr(cs.references).map((r) => ({ url: str(r.url) ?? '', title: str(r.title) ?? '' }));
        const v = {
            atlasId, name: str(cs.name) ?? '', summary: str(cs.summary),
            incidentDate: str(cs['incident-date']), reporter: str(cs.reporter),
            target: str(cs.target), actor: str(cs.actor),
            techniqueIds: steps.map((s) => s.technique).filter(Boolean),
            procedureSteps: steps, references: refs,
            url: `https://atlas.mitre.org/studies/${atlasId}`,
        };
        await db.insert(atlasCaseStudies).values(v).onConflictDoUpdate({ target: atlasCaseStudies.atlasId, set: { ...v, updatedAt: new Date() } });
    }
    log.info('ATLAS ingested', { tactics: tactics.length, techniques: techniques.length, mitigations: mitigations.length, caseStudies: caseStudies.length });
    return { tactics: tactics.length, techniques: techniques.length, mitigations: mitigations.length, caseStudies: caseStudies.length };
}

// ── FiGHT ────────────────────────────────────────────────────────────────────

export async function ingestFight(): Promise<{ tactics: number; techniques: number; mitigations: number; groups: number; groupTechniques: number }> {
    const data = await fetchYaml(FIGHT_URL);
    const tactics = arr(data.tactics);
    const techniques = arr(data.techniques);
    const mitigations = arr(data.mitigations);
    const groups = arr(data.groups);

    for (const t of tactics) {
        const mitreId = str(t.id) ?? '';
        const v = {
            mitreId, name: str(t.name) ?? '', description: str(t.description),
            shortName: str(t['short-name']) ?? (str(t.name) ?? '').toLowerCase().replace(/ /g, '-'),
            url: `https://fight.mitre.org/tactics/${mitreId}`,
        };
        await db.insert(fightTactics).values(v).onConflictDoUpdate({ target: fightTactics.mitreId, set: { ...v, updatedAt: new Date() } });
    }
    for (const t of techniques) {
        const fightId = str(t.id) ?? '';
        // addendum platforms (FiGHT has no standard `platforms` field)
        const platforms = [...new Set(arr(t.addendums).flatMap((a) => (Array.isArray(a.platforms) ? (a.platforms as string[]) : [])))];
        const jarr = (k: string) => (Array.isArray(t[k]) ? (t[k] as Record<string, unknown>[]) : []);
        const v = {
            fightId, name: str(t.name) ?? '', description: str(t.description), bluf: str(t.bluf),
            status: str(t.status), architectureSegment: str(t['architecture-segment']), typecode: str(t.typecode),
            tacticIds: ids(t.tactics), platforms,
            preconditions: jarr('preconditions'), postconditions: jarr('postconditions'),
            criticalAssets: jarr('criticalassets'), detections: jarr('detections'),
            procedureExamples: jarr('procedureexamples'), references: jarr('references'),
            url: `https://fight.mitre.org/techniques/${fightId}`,
        };
        // Parsed-YAML jsonb arrays are correct at runtime but typed loosely vs the
        // schema's $type<{name,description}[]> — cast so drizzle's typed insert accepts them.
        await db.insert(fightTechniques).values(v as never).onConflictDoUpdate({ target: fightTechniques.fightId, set: { ...v, updatedAt: new Date() } as never });
    }
    for (const m of mitigations) {
        const fightId = str(m.id) ?? '';
        const v = {
            fightId, name: str(m.name) ?? '', description: str(m.description),
            techniqueIds: ids(m.techniques), url: `https://fight.mitre.org/mitigations/${fightId}`,
        };
        await db.insert(fightMitigations).values(v).onConflictDoUpdate({ target: fightMitigations.fightId, set: { ...v, updatedAt: new Date() } });
    }

    // Groups → threat_actors (stix_id "fight--<id>") + group→technique edges.
    // Reset the mapping table first so a re-ingest is idempotent (the table has
    // no natural key, so plain re-insert would duplicate).
    await db.delete(fightGroupTechniques);
    let groupTechniques = 0;
    for (const g of groups) {
        const groupId = str(g.id) ?? '';
        const stixId = `fight--${groupId}`;
        const actor = {
            stixId, name: str(g.name) ?? '', aliases: (Array.isArray(g.aliases) ? (g.aliases as string[]) : []),
            description: str(g.description), primaryMotivation: 'telco-targeting', sophistication: 'advanced',
        };
        const [row] = await db.insert(threatActors).values(actor)
            .onConflictDoUpdate({ target: threatActors.stixId, set: { name: actor.name, description: actor.description, aliases: actor.aliases, updatedAt: new Date() } })
            .returning({ id: threatActors.id });
        const actorId = row?.id ?? groupId;
        for (const t of arr(g.techniques)) {
            await db.insert(fightGroupTechniques).values({
                groupId: actorId, groupName: str(g.name) ?? '',
                fightTechniqueId: str(t.id) ?? '', techniqueName: str(t.name) ?? '', description: str(t.use),
            });
            groupTechniques++;
        }
    }
    log.info('FiGHT ingested', { tactics: tactics.length, techniques: techniques.length, mitigations: mitigations.length, groups: groups.length, groupTechniques });
    return { tactics: tactics.length, techniques: techniques.length, mitigations: mitigations.length, groups: groups.length, groupTechniques };
}

export async function ingestFrameworks() {
    return { atlas: await ingestAtlas(), fight: await ingestFight() };
}

export const __testing = { fetchYaml, ids };
