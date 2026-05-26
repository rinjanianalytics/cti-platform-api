/**
 * BullMQ Workers — Barrel Re-export
 *
 * Background workers that process jobs from queues.
 * Uses structured JSON logging via lib/logger.
 */

// Feed sync + IOC enrichment workers
export { feedSyncWorker, enrichmentWorker } from './workers/feedWorkers';

// Feed-batch flow parent — stamps `feed_sync_runs.enriched_at` once all
// per-IOC enrichment children settle.
export { feedBatchWorker } from './workers/feedBatchWorker';

// AI analysis + notification + alerts workers
export { aiAnalysisWorker, notificationWorker, alertsWorker, alertStore } from './workers/utilityWorkers';

// Neo4j sync worker
export { neo4jSyncWorker } from './workers/syncWorkers';

// CVE enrichment worker
export { cveEnrichmentWorker } from './workers/cveEnrichmentWorker';

// Data lifecycle + maintenance worker
export { retentionWorker } from './workers/retentionWorker';

// Event handlers + startup/shutdown
export { startWorkers, stopWorkers } from './workers/workerEvents';
