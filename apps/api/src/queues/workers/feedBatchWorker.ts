/**
 * Feed-batch flow parent worker.
 *
 * Each feed-sync run that triggers auto-enrichment fans out into a
 * FlowProducer batch: parent = "batch-<runId>" in queue `feed-batch`,
 * children = per-IOC enrichment jobs in `ioc-enrichment`. BullMQ holds
 * the parent until every child settles (success OR failure), then runs
 * this handler.
 *
 * The handler does one thing: stamp `feed_sync_runs.enriched_at` so the
 * admin /feeds history page can render "ingested at X, all enriched by Y."
 * The job's `getChildrenValues()` could be used to compute per-child
 * success/failure counts but we keep it minimal — anything fancier is a
 * separate slice once we know what analysts actually want to see.
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { createLogger } from '../../lib/logger';
import { markFeedSyncRunEnriched } from '../../services/configStore';

interface FeedBatchJobData {
    runId: string;
    source: string;
    ingestedCount: number;
}

export const feedBatchWorker = new Worker<FeedBatchJobData>(
    'feed-batch',
    async (job: Job<FeedBatchJobData>) => {
        const log = createLogger('FeedBatch');
        const { runId, source, ingestedCount } = job.data;

        // BullMQ only invokes this handler once all children have settled.
        // Count how many children produced a result (success or failure are
        // both "settled" for our purposes) so the dashboard can show
        // "X/N enriched" if it ever wants to.
        const childValues = await job.getChildrenValues();
        const childrenDone = Object.keys(childValues).length;

        log.info('Flow batch settled', { runId, source, ingestedCount, childrenDone });

        await markFeedSyncRunEnriched(runId, childrenDone);

        return { runId, childrenDone };
    },
    {
        connection,
        concurrency: 4,
    },
);
