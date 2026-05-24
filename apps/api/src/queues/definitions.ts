/**
 * BullMQ Queue Definitions
 *
 * All queues use the persistent Redis instance (REDIS_QUEUE_URL).
 * Failed jobs that exhaust all retries are moved to the Dead Letter Queue.
 */

import { Queue } from 'bullmq';
import { connection } from '../services/redis';

// ============================================================================
// Dead Letter Queue — catches all jobs that exhaust retries
// ============================================================================

export const deadLetterQueue = new Queue('dead-letter', {
    connection,
    defaultJobOptions: {
        removeOnComplete: false,    // Keep for inspection
        removeOnFail: false,        // Never auto-remove dead letters
    },
});

// ============================================================================
// Helper: move failed job to DLQ
// ============================================================================

export async function moveToDeadLetter(
    sourceQueue: string,
    jobId: string,
    jobData: Record<string, unknown>,
    failedReason: string,
): Promise<void> {
    await deadLetterQueue.add('dead-letter', {
        originalQueue: sourceQueue,
        originalJobId: jobId,
        data: jobData,
        failedReason,
        failedAt: new Date().toISOString(),
    }, {
        attempts: 1,
    });
}

// ============================================================================
// Feed & Ingestion Queues
// ============================================================================

export const feedSyncQueue = new Queue('feed-sync', {
    connection,
    defaultJobOptions: {
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 500 },
    },
});

export const enrichmentQueue = new Queue('ioc-enrichment', {
    connection,
    defaultJobOptions: {
        attempts: 3,
        backoff: { type: 'exponential', delay: 3000 },
        removeOnComplete: { count: 500 },
        removeOnFail: { count: 1000 },
    },
});

export const cveEnrichmentQueue = new Queue('cve-enrichment', {
    connection,
    defaultJobOptions: {
        attempts: 2,
        backoff: { type: 'fixed', delay: 30000 },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 200 },
    },
});

// ============================================================================
// Processing Queues
// ============================================================================

export const aiAnalysisQueue = new Queue('ai-analysis', {
    connection,
    defaultJobOptions: {
        attempts: 2,
        backoff: { type: 'fixed', delay: 10000 },
        removeOnComplete: { count: 200 },
        removeOnFail: { count: 500 },
    },
});

export const neo4jSyncQueue = new Queue('neo4j-sync', {
    connection,
    defaultJobOptions: {
        attempts: 2,
        backoff: { type: 'fixed', delay: 10000 },
        removeOnComplete: { count: 50 },
        removeOnFail: { count: 100 },
    },
});

// ============================================================================
// Notification & Alert Queues
// ============================================================================

export const notificationQueue = new Queue('notifications', {
    connection,
    defaultJobOptions: {
        attempts: 5,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: { count: 1000 },
        removeOnFail: { count: 2000 },
    },
});

export const alertsQueue = new Queue('alerts', {
    connection,
    defaultJobOptions: {
        attempts: 3,
        backoff: { type: 'exponential', delay: 1000 },
        removeOnComplete: { count: 5000 },
        removeOnFail: { count: 1000 },
    },
});

// ============================================================================
// Maintenance Queues
// ============================================================================

export const maintenanceQueue = new Queue('maintenance', {
    connection,
    defaultJobOptions: {
        attempts: 2,
        backoff: { type: 'fixed', delay: 60000 },
        removeOnComplete: { count: 50 },
        removeOnFail: { count: 100 },
    },
});
