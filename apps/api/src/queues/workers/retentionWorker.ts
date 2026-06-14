/**
 * Retention Worker — Confidence Decay & Data Lifecycle
 *
 * Handles two maintenance job types:
 *   - confidence-decay: Applies exponential decay to IOC risk scores
 *   - data-retention: Prunes old audit logs, resolved alerts, and stale IOCs
 */

import { Worker } from 'bullmq';
import { connection } from '../../services/redis';
import { db, sql, rawQuery } from '@rinjani/db';
import { batchDecay } from '../../services/confidenceDecay';
import { escSql } from '../../lib/sanitize';
import { createLogger } from '../../lib/logger';
import { runActorTtpDiff } from '../../services/actorTtpDiffer';
import { scanAllWatchterms } from '../../services/ahmiaSearch';
import { runGistScan } from '../../services/gistMonitor';
import { pruneDecayedFromOpenSearch } from '../../services/opensearchPrune';
import { rescoreAll } from '../../services/scoringEngine';
import { runJobWithSpan } from '../tracing';

const log = createLogger('RetentionWorker');

const BATCH_SIZE = 500;

// ============================================================================
// Worker
// ============================================================================

export const retentionWorker = new Worker(
    'maintenance',
    async (job) => runJobWithSpan('maintenance', job, async () => {
        switch (job.name) {
            case 'confidence-decay':
                return await processConfidenceDecay();
            case 'data-retention':
                return await processDataRetention();
            case 'mitre-ttp-diff':
                return await runActorTtpDiff();
            case 'dark-web-ahmia-scan':
                return await scanAllWatchterms();
            case 'paste-gist-scan':
                return await runGistScan();
            case 'opensearch-prune':
                return await pruneDecayedFromOpenSearch();
            case 'risk-score-backfill':
                // Scores every IOC at risk_score = 0 / NULL using the
                // existing scoringEngine pipeline (source confidence +
                // VT detections + graph centrality + freshness + MITRE
                // coverage). One-shot work in steady state — the
                // stream-consumer scoring hook keeps newly-ingested
                // IOCs scored — so the per-tick result.scored count
                // drops to zero once the backfill is complete.
                return await rescoreAll(100, { onlyUnscored: true });
            default:
                log.warn('Unknown maintenance job type', { name: job.name });
                return { skipped: true };
        }
    }),
    {
        connection,
        concurrency: 1,
        limiter: { max: 1, duration: 60_000 },
    },
);

// ============================================================================
// Confidence Decay
// ============================================================================

async function processConfidenceDecay() {
    log.info('Starting confidence decay batch');

    let totalProcessed = 0;
    let totalUpdated = 0;
    let totalNewlyDecayed = 0;
    let offset = 0;

    while (true) {
        // Fetch IOCs with last_seen older than 1 day. Skip rows already
        // flagged decayed — they don't need re-stamping, and excluding
        // them lets the WHERE clause use iocs_decayed_at_partial_idx.
        //
        // No `risk_score > 0` filter: with 266k IOCs on prod, ALL of them
        // currently have risk_score = 0 (the scoring engine hasn't been
        // backfilling historical rows). Gating the SELECT on the score
        // meant zero rows ever decayed — see the 2026-06-13 retention run
        // logged `totalProcessed: 0` even with 260k stale IOCs eligible.
        // The score-write path keeps the originalScore > 0 guard below
        // so unscored rows don't get materialized into low-confidence
        // scores; the marker path runs for every stale row regardless.
        const result = await rawQuery<{ id: string; riskScore: number; lastSeen: string; type: string }>(`
            SELECT id, risk_score as "riskScore", last_seen::text as "lastSeen", type
            FROM iocs
            WHERE last_seen < NOW() - INTERVAL '1 day'
              AND decayed_at IS NULL
            ORDER BY last_seen ASC
            LIMIT ${BATCH_SIZE} OFFSET ${offset}
        `);

        const rows = result.rows || result || [];
        if (rows.length === 0) break;

        // Calculate decay. `decayed` carries per-IOC `isStale` based on the
        // per-type staleDays threshold in DECAY_RATES — that's the signal
        // for the marker UPDATE below.
        //
        // `originalScore > 0` guards the score-write path: batchDecay
        // computes max(minScore, baseScore × e^(-λ·days)), which for
        // baseScore=0 collapses to minScore (e.g. 10 for ipv4-addr). We
        // do NOT want to backfill the 260k unscored rows up to their
        // type's minScore — that would invent confidence the scoring
        // engine never asserted. Score updates apply only to already-
        // scored IOCs; the marker path runs on every stale row.
        const decayed = batchDecay(rows);
        const toUpdate = decayed.filter(d => d.decayedScore !== d.originalScore && d.originalScore > 0);
        const toMarkDecayed = decayed.filter(d => d.isStale);

        // Bulk-update risk_score for IOCs whose decayed score changed.
        if (toUpdate.length > 0) {
            const cases = toUpdate
                .map(d => `WHEN '${escSql(d.id)}' THEN ${d.decayedScore}`)
                .join(' ');
            const ids = toUpdate
                .map(d => `'${escSql(d.id)}'`)
                .join(',');

            await db.execute(sql.raw(`
                UPDATE iocs
                SET risk_score = CASE id ${cases} END,
                    updated_at = NOW()
                WHERE id IN (${ids})
            `));
        }

        // Stamp `decayed_at = NOW()` on IOCs that crossed their per-type
        // staleness threshold this run. We can keep this UPDATE small —
        // the SELECT above already excluded rows that were previously
        // marked, so every row in toMarkDecayed is a fresh transition.
        // Safe to run alongside the risk_score UPDATE: separate WHERE
        // clauses, and the iocs_undecay trigger only fires on last_seen
        // changes, which neither UPDATE touches.
        if (toMarkDecayed.length > 0) {
            const staleIds = toMarkDecayed
                .map(d => `'${escSql(d.id)}'`)
                .join(',');

            await db.execute(sql.raw(`
                UPDATE iocs
                SET decayed_at = NOW(),
                    updated_at = NOW()
                WHERE id IN (${staleIds})
                  AND decayed_at IS NULL
            `));
        }

        totalProcessed += rows.length;
        totalUpdated += toUpdate.length;
        totalNewlyDecayed += toMarkDecayed.length;
        offset += BATCH_SIZE;

        // Safety: limit to 10k rows per run
        if (offset >= 10_000) break;
    }

    log.info('Confidence decay complete', { totalProcessed, totalUpdated, totalNewlyDecayed });
    return { totalProcessed, totalUpdated, totalNewlyDecayed };
}

// ============================================================================
// Data Retention
// ============================================================================

async function processDataRetention() {
    log.info('Starting data retention cleanup');

    const results = {
        auditLogsDeleted: 0,
        alertsDeleted: 0,
        staleIocsArchived: 0,
    };

    // 1. Delete audit logs older than 90 days
    try {
        const auditResult = await rawQuery(`
            DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days'
        `);
        results.auditLogsDeleted = (auditResult as { rows: Record<string, unknown>[] }).rows?.length || 0;
        log.info('Pruned old audit logs', { deleted: results.auditLogsDeleted });
    } catch (err) {
        log.warn('Audit log cleanup failed (table may not exist)', { error: (err as Error).message });
    }

    // 2. Delete acknowledged alerts older than 30 days
    try {
        const alertResult = await rawQuery(`
            DELETE FROM alerts WHERE acknowledged = true AND created_at < NOW() - INTERVAL '30 days'
        `);
        results.alertsDeleted = (alertResult as { rows: Record<string, unknown>[] }).rows?.length || 0;
        log.info('Pruned old acknowledged alerts', { deleted: results.alertsDeleted });
    } catch (err) {
        log.warn('Alert cleanup failed (table may not exist)', { error: (err as Error).message });
    }

    // 3. Soft-archive stale IOCs (set status to 'archived')
    //    Staleness is 2× the type's staleDays threshold (e.g., IPs: 60 days, hashes: 360 days)
    try {
        const archiveResult = await rawQuery(`
            UPDATE iocs
            SET status = 'archived', updated_at = NOW()
            WHERE status != 'archived'
              AND risk_score <= 10
              AND last_seen < NOW() - INTERVAL '120 days'
        `);
        results.staleIocsArchived = (archiveResult as { rows: Record<string, unknown>[] }).rows?.length || 0;
        log.info('Archived stale IOCs', { archived: results.staleIocsArchived });
    } catch (err) {
        log.warn('IOC archival failed', { error: (err as Error).message });
    }

    log.info('Data retention complete', results);
    return results;
}
