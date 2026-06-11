/**
 * Brand monitor worker — Phase 5 #1.
 *
 * Runs on the `brand-monitor` queue. Each scheduled tick (default 6h)
 * walks every enabled `monitored_domains` row, generates dnstwist-style
 * permutations, DNS-resolves each, and upserts `brand_alerts` for
 * anything that resolves.
 *
 * Concurrency = 1 (the worker iterates internally and batches DNS
 * resolves to 16-wide). Single attempt: the work is idempotent; a
 * failed sweep can just wait for the next 6h tick rather than retrying
 * immediately and doubling the load.
 */
import { Worker } from 'bullmq';
import { connection } from '../../services/redis';
import { createLogger } from '../../lib/logger';
import { sweepAllMonitoredDomains } from '../../services/brandMonitor';
import { runJobWithSpan } from '../tracing';

const log = createLogger('BrandMonitorWorker');

export const brandMonitorWorker = new Worker(
    'brand-monitor',
    async (job) => runJobWithSpan('brand-monitor', job, async () => {
        if (job.name !== 'brand-sweep') {
            log.warn('unknown brand-monitor job type', { name: job.name });
            return { skipped: true };
        }
        const summaries = await sweepAllMonitoredDomains();
        return {
            domainsSwept: summaries.length,
            totalHitsCreated: summaries.reduce((a, s) => a + s.hitsCreated, 0),
            totalHitsUpdated: summaries.reduce((a, s) => a + s.hitsUpdated, 0),
        };
    }),
    {
        connection,
        concurrency: 1,
        // Cap to one sweep per 5 minutes — guards against a manual `add`
        // storm or misconfigured 1-minute schedule pegging the DNS resolver.
        limiter: { max: 1, duration: 300_000 },
    },
);
