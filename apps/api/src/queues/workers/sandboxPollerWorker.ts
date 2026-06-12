/**
 * Sandbox poller worker. Phase 4 #5b.
 *
 * Runs on the `sandbox-polling` queue. Each scheduled tick fans out
 * `refreshSandboxReport` over every non-terminal row.
 *
 * Selection rules:
 *   - status IN ('queued', 'running')
 *   - vendor_task_id IS NOT NULL  (can't poll without one)
 *   - submitted_at >= NOW() - INTERVAL '1 day'  (give up after a day —
 *     vendors typically time out an analysis far sooner; this stops us
 *     burning the API quota on dead submissions forever)
 *
 * Concurrency:
 *   - Worker concurrency = 1 (the work is one batch per tick)
 *   - Per-batch parallelism is bounded by `MAX_PARALLEL_REFRESH` so a
 *     full queue doesn't fire 200 vendor calls at once.
 *
 * Returns a summary suitable for the BullMQ dashboard / scheduler
 * audit trail.
 */
import { Worker } from 'bullmq';
import { connection } from '../../services/redis';
import { db, sql } from '@rinjani/db';
import { sandboxReports } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';
import { runJobWithSpan } from '../tracing';
import { refreshSandboxReport } from '../../services/sandbox';

const log = createLogger('SandboxPoller');

const MAX_PARALLEL_REFRESH = 8;

export interface PollOutcome {
    candidates: number;
    refreshed: number;
    completed: number;
    failed: number;
    skipped: number;
    durationMs: number;
}

export async function pollPendingReports(): Promise<PollOutcome> {
    const t0 = Date.now();
    const rows = await db.select({ id: sandboxReports.id }).from(sandboxReports).where(sql`
        ${sandboxReports.status} IN ('queued', 'running')
        AND ${sandboxReports.vendorTaskId} IS NOT NULL
        AND ${sandboxReports.submittedAt} >= NOW() - INTERVAL '1 day'
    `);

    if (rows.length === 0) {
        log.debug('no pending sandbox reports to poll');
        return { candidates: 0, refreshed: 0, completed: 0, failed: 0, skipped: 0, durationMs: Date.now() - t0 };
    }

    const out: PollOutcome = {
        candidates: rows.length,
        refreshed: 0, completed: 0, failed: 0, skipped: 0,
        durationMs: 0,
    };

    // Window the row list into MAX_PARALLEL_REFRESH at a time.
    for (let i = 0; i < rows.length; i += MAX_PARALLEL_REFRESH) {
        const window = rows.slice(i, i + MAX_PARALLEL_REFRESH);
        await Promise.all(window.map(async ({ id }) => {
            try {
                const updated = await refreshSandboxReport(id);
                if (!updated) {
                    out.skipped++;
                    return;
                }
                out.refreshed++;
                if (updated.status === 'completed') out.completed++;
                if (updated.status === 'failed' || updated.status === 'timeout') out.failed++;
            } catch (err) {
                log.warn('sandbox refresh threw', { id, error: (err as Error).message });
                out.skipped++;
            }
        }));
    }

    out.durationMs = Date.now() - t0;
    log.info('sandbox poll batch complete', { ...out });
    return out;
}

export const sandboxPollerWorker = new Worker(
    'sandbox-polling',
    async (job) => runJobWithSpan('sandbox-polling', job, async () => {
        if (job.name !== 'sandbox-poll') {
            log.warn('unknown sandbox-polling job type', { name: job.name });
            return { skipped: true };
        }
        return pollPendingReports();
    }),
    {
        connection,
        concurrency: 1,
        // Cap to two ticks per minute — guards against a misconfigured
        // schedule (or a manual `add` storm) hammering vendor APIs.
        limiter: { max: 2, duration: 60_000 },
    },
);
