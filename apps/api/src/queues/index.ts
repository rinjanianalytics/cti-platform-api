/**
 * BullMQ Queue Definitions — Barrel
 *
 * Sub-modules:
 *   - queues/types.ts       → Job data interfaces
 *   - queues/definitions.ts → Queue instances
 *   - queues/events.ts      → QueueEvents for monitoring
 *   - queues/stats.ts       → Queue registry & stats helper
 */

// Types
export type {
    FeedSyncJobData, EnrichmentJobData, AIAnalysisJobData,
    NotificationJobData, AlertJobData, Neo4jSyncJobData,
    CVEEnrichmentJobData,
} from './types';

// Queue instances
export {
    feedSyncQueue, enrichmentQueue, aiAnalysisQueue, notificationQueue,
    alertsQueue, neo4jSyncQueue, cveEnrichmentQueue,
    maintenanceQueue,
} from './definitions';

// Events
export {
    feedSyncEvents, enrichmentEvents, aiAnalysisEvents, notificationEvents,
    alertsEvents, neo4jSyncEvents, cveEnrichmentEvents,
} from './events';

// Registry & stats
export { allQueues, getQueueStats } from './stats';
