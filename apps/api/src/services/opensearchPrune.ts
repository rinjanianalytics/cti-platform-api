/**
 * OpenSearch Decayed-IOC Pruner
 *
 * Drops documents from the OpenSearch indices for IOCs that the
 * confidenceDecay job (apps/api/src/queues/workers/retentionWorker.ts)
 * has marked as decayed (iocs.decayed_at IS NOT NULL — see migration
 * 0058_ioc_decay_marker.sql).
 *
 * Why drop instead of soft-hide:
 *   - Indices grow unbounded otherwise; this is the cheap path to
 *     bounded-size search on a single-droplet OpenSearch deployment.
 *   - The postgres row stays — forensic queries and the underlying
 *     audit trail are unaffected. If an analyst sights a decayed IOC
 *     again, the iocs_undecay_on_resight trigger flips decayed_at back
 *     to NULL, and the next reindex (or a feed-sync re-upsert) re-adds
 *     it to OpenSearch automatically.
 *   - Conceptually this is the "cold tier" the roadmap's "OpenSearch
 *     ILM" line was after, except we have one node so cold = absent.
 *
 * Scope:
 *   - Only touches IOC documents. Vulnerabilities + threat actors are
 *     long-lived reference data — no decay applies and the indices
 *     don't grow unbounded the same way.
 *   - Iterates postgres in batches of BATCH so a single run doesn't
 *     attempt a 100k-id `ids` query against OpenSearch (which would
 *     overflow the default query size limit). The MAX_ROWS guardrail
 *     caps wall-clock per job; subsequent jobs pick up where this one
 *     left off because the SELECT only matches still-present rows.
 */

import { getOpenSearchClient, INDICES } from './opensearch/client';
import { rawQuery } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('OpenSearchPrune');

const BATCH = 500;
const MAX_ROWS = 50_000;

interface PruneSummary {
    /** Number of decayed IOC IDs walked through this run. */
    candidates: number;
    /** Sum of `deleted` from each OpenSearch delete-by-query response. */
    documentsRemoved: number;
    /** Per-index breakdown for the maintenance audit trail. */
    perIndex: Record<string, number>;
    durationMs: number;
}

/** Indices that hold IOC documents and should be pruned. */
const TARGET_INDICES = [INDICES.iocs, INDICES.unified];

export async function pruneDecayedFromOpenSearch(): Promise<PruneSummary> {
    const t0 = Date.now();
    const client = getOpenSearchClient();

    let candidates = 0;
    let documentsRemoved = 0;
    const perIndex: Record<string, number> = Object.fromEntries(
        TARGET_INDICES.map(i => [i, 0]),
    );

    let offset = 0;
    while (offset < MAX_ROWS) {
        // Pull a batch of decayed IDs. ORDER BY decayed_at ASC so we
        // process the oldest first — keeps results stable across paged
        // calls and means a re-run after a crash makes forward progress
        // even without checkpointing.
        const result = await rawQuery<{ id: string }>(`
            SELECT id
            FROM iocs
            WHERE decayed_at IS NOT NULL
            ORDER BY decayed_at ASC
            LIMIT ${BATCH} OFFSET ${offset}
        `);
        const rows = result.rows || result || [];
        if (rows.length === 0) break;

        const ids = rows.map(r => r.id);
        candidates += ids.length;

        for (const indexName of TARGET_INDICES) {
            try {
                const res = await client.delete_by_query({
                    index: indexName,
                    body: { query: { ids: { values: ids } } },
                    // Don't wait for an explicit refresh — these documents
                    // are stale anyway; the refresh interval is good
                    // enough and saves cluster CPU on a single-node setup.
                    refresh: false,
                });
                const removed = (res.body as { deleted?: number })?.deleted ?? 0;
                perIndex[indexName] += removed;
                documentsRemoved += removed;
            } catch (err) {
                // Index-missing is the common case before first index;
                // log and keep going so the rest of the run completes.
                log.warn(`prune-by-query failed against ${indexName}`, {
                    error: (err as Error).message,
                });
            }
        }

        offset += BATCH;
    }

    const summary: PruneSummary = {
        candidates,
        documentsRemoved,
        perIndex,
        durationMs: Date.now() - t0,
    };
    log.info('OpenSearch prune complete', summary as unknown as Record<string, unknown>);
    return summary;
}
