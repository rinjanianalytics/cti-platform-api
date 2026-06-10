/**
 * Threat-actor TTP differ — Phase 5 #2.
 *
 * MITRE updates per-actor technique lists on a roughly weekly cadence
 * — new attributions appear, deprecated ones drop. Today we lose that
 * signal: each MITRE sync overwrites the relationships table and the
 * delta evaporates. This service runs after MITRE sync (or ad-hoc),
 * compares the **live** technique set per actor against `actor_ttp_state`,
 * and emits add/remove rows into `actor_ttp_changes`.
 *
 * The pure diff function (`computeTtpDiff`) is exported so the test
 * suite can exercise the set-difference logic without DB.
 */
import { db, eq, and, sql, inArray } from '@rinjani/db';
import {
    actorTtpState, actorTtpChanges,
    type TtpChangeType,
} from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('ActorTtpDiffer');

// ============================================================================
// Types + pure diff
// ============================================================================

export interface ActorTtpSet {
    actorId: string;
    techniqueIds: Set<string>;
}

export interface TtpDiffEntry {
    actorId: string;
    techniqueId: string;
    changeType: TtpChangeType;
}

/**
 * Compare a previous snapshot against the current live set. Pure — no
 * I/O. The previous map is keyed by `actorId`, value is the Set of
 * techniques observed at the last diff run; the current array is the
 * fresh snapshot. Returns one entry per add/remove.
 *
 * Notes on actor lifecycle:
 *   - An actor present in `current` but absent from `prev` simply has
 *     all its techniques emitted as 'added'.
 *   - An actor present in `prev` but absent from `current` (the MITRE
 *     row was deprecated) has all its techniques emitted as 'removed'.
 */
export function computeTtpDiff(
    prev: Map<string, Set<string>>,
    current: ActorTtpSet[],
): TtpDiffEntry[] {
    const out: TtpDiffEntry[] = [];

    // Build a fast lookup for the current side.
    const currentByActor = new Map<string, Set<string>>();
    for (const a of current) currentByActor.set(a.actorId, a.techniqueIds);

    // Adds + confirmations.
    for (const [actorId, currTechs] of currentByActor) {
        const prevTechs = prev.get(actorId) ?? new Set<string>();
        for (const t of currTechs) {
            if (!prevTechs.has(t)) {
                out.push({ actorId, techniqueId: t, changeType: 'added' });
            }
        }
    }

    // Removes — anything in prev but not in current.
    for (const [actorId, prevTechs] of prev) {
        const currTechs = currentByActor.get(actorId) ?? new Set<string>();
        for (const t of prevTechs) {
            if (!currTechs.has(t)) {
                out.push({ actorId, techniqueId: t, changeType: 'removed' });
            }
        }
    }

    return out;
}

// ============================================================================
// Live snapshot — pulls from the existing `relationships` table
// ============================================================================

interface RelationshipRow { source_id: string; target_id: string }

/**
 * Read the current actor → techniques set from the existing
 * `relationships` table. Filters on the STIX 2.1 vocabulary that the
 * MITRE feed sync writes:
 *
 *   - source_type='intrusion-set'  (STIX SDO for threat groups)
 *   - target_type='attack-pattern' (STIX SDO for techniques)
 *   - relationship_type='uses'
 *
 * The relationships table was wired up by the MITRE feed sync long
 * before Phase 5 — see packages/db/src/schema/mitre.ts. We don't need
 * a new ingest path here, just a read.
 *
 * 2026-06-09: original filter used `threat_actor` / `technique`, which
 * are our internal Phase 1 names — MITRE never writes those values
 * through `feed-sync:mitre`. Production live-test on 2026-06-09 found
 * the relationships table holds 49,927 rows under the STIX vocab and
 * zero under the old filter. Fix verified end-to-end on the droplet.
 */
export async function snapshotCurrentTtps(): Promise<ActorTtpSet[]> {
    const result = await db.execute(sql`
        SELECT source_id, target_id
        FROM relationships
        WHERE source_type = 'intrusion-set'
          AND target_type = 'attack-pattern'
          AND relationship_type = 'uses'
    `);

    // postgres-js returns an array-like, pg returns { rows: [...] }. Match the
    // normalization in rawQuery() (packages/db/src/client.ts) so the snapshot
    // works regardless of which driver shape db.execute() returns at runtime.
    // Pre-fix, this code only handled the pg shape — postgres-js prod returned
    // the rows directly as an array, `result.rows` was undefined, and the
    // differ logged "actorsInLive: 0" while the relationships table held 55k+
    // matching tuples.
    const rows: RelationshipRow[] = Array.isArray(result)
        ? (result as unknown as RelationshipRow[])
        : ((result as unknown as { rows?: RelationshipRow[] }).rows ?? []);
    const grouped = new Map<string, Set<string>>();
    for (const r of rows) {
        let set = grouped.get(r.source_id);
        if (!set) { set = new Set<string>(); grouped.set(r.source_id, set); }
        set.add(r.target_id);
    }

    return [...grouped.entries()].map(([actorId, techniqueIds]) => ({
        actorId,
        techniqueIds,
    }));
}

// ============================================================================
// Differ runner — writes to actor_ttp_state + actor_ttp_changes
// ============================================================================

export interface DifferSummary {
    actorsInLive: number;
    actorsInPriorSnapshot: number;
    techniquesInLive: number;
    techniquesInPriorSnapshot: number;
    added: number;
    removed: number;
    /** Tuples present in both snapshots — `confirmed_at` bumped to now. */
    confirmed: number;
    durationMs: number;
    /**
     * True when the prior snapshot was empty. The first run records every
     * live tuple as a baseline (add), which is honest but means the change
     * log gets a huge initial burst — UI / alerts can filter on
     * `first_run_baseline` from the timestamp boundary if they want to
     * ignore the bootstrap.
     */
    isBaselineRun: boolean;
}

export async function runActorTtpDiff(): Promise<DifferSummary> {
    const t0 = Date.now();

    const current = await snapshotCurrentTtps();
    const prevRows = await db.select().from(actorTtpState);

    const prev = new Map<string, Set<string>>();
    for (const r of prevRows) {
        let set = prev.get(r.actorId);
        if (!set) { set = new Set<string>(); prev.set(r.actorId, set); }
        set.add(r.techniqueId);
    }

    const diff = computeTtpDiff(prev, current);
    const adds = diff.filter(d => d.changeType === 'added');
    const removes = diff.filter(d => d.changeType === 'removed');

    // Write the change log + reconcile the state table. Both happen in one
    // transaction so a mid-run failure doesn't leave a half-applied state.
    await db.transaction(async (tx) => {
        if (diff.length > 0) {
            await tx.insert(actorTtpChanges).values(diff.map(d => ({
                actorId: d.actorId,
                techniqueId: d.techniqueId,
                changeType: d.changeType,
            })));
        }

        // Insert added tuples; bump confirmed_at on existing ones; delete removed.
        const now = new Date();
        if (adds.length > 0) {
            await tx.insert(actorTtpState).values(adds.map(a => ({
                actorId: a.actorId,
                techniqueId: a.techniqueId,
                observedAt: now,
                confirmedAt: now,
            }))).onConflictDoUpdate({
                target: [actorTtpState.actorId, actorTtpState.techniqueId],
                set: { confirmedAt: now },
            });
        }

        // Confirm tuples still present in current (and prev). Done as a single
        // UPDATE … WHERE (actor_id, technique_id) IN (…). Bulk inArray on a
        // composite key isn't natively supported; we do a per-actor batched
        // UPDATE instead.
        for (const a of current) {
            const techList = [...a.techniqueIds];
            if (techList.length === 0) continue;
            await tx.update(actorTtpState)
                .set({ confirmedAt: now })
                .where(and(
                    eq(actorTtpState.actorId, a.actorId),
                    inArray(actorTtpState.techniqueId, techList),
                ));
        }

        if (removes.length > 0) {
            // Per-actor DELETE for the same reason (composite-key IN isn't native).
            const byActor = new Map<string, string[]>();
            for (const r of removes) {
                let list = byActor.get(r.actorId);
                if (!list) { list = []; byActor.set(r.actorId, list); }
                list.push(r.techniqueId);
            }
            for (const [actorId, techList] of byActor) {
                await tx.delete(actorTtpState).where(and(
                    eq(actorTtpState.actorId, actorId),
                    inArray(actorTtpState.techniqueId, techList),
                ));
            }
        }
    });

    let livePairs = 0;
    for (const a of current) livePairs += a.techniqueIds.size;

    const summary: DifferSummary = {
        actorsInLive: current.length,
        actorsInPriorSnapshot: prev.size,
        techniquesInLive: livePairs,
        techniquesInPriorSnapshot: prevRows.length,
        added: adds.length,
        removed: removes.length,
        confirmed: livePairs - adds.length,
        durationMs: Date.now() - t0,
        isBaselineRun: prevRows.length === 0,
    };

    log.info('TTP diff complete', summary as unknown as Record<string, unknown>);
    return summary;
}
