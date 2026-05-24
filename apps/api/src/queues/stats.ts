/**
 * Queue Registry & Stats
 */

import {
    feedSyncQueue, enrichmentQueue, aiAnalysisQueue, notificationQueue,
    alertsQueue, neo4jSyncQueue, cveEnrichmentQueue,
    maintenanceQueue,
} from './definitions';

export const allQueues = [
    feedSyncQueue,
    enrichmentQueue,
    aiAnalysisQueue,
    notificationQueue,
    alertsQueue,
    neo4jSyncQueue,
    cveEnrichmentQueue,
    maintenanceQueue,
];

/**
 * Get queue statistics
 */
export async function getQueueStats() {
    const stats = await Promise.all(
        allQueues.map(async (queue) => {
            const [waiting, active, completed, failed, delayed] = await Promise.all([
                queue.getWaitingCount(),
                queue.getActiveCount(),
                queue.getCompletedCount(),
                queue.getFailedCount(),
                queue.getDelayedCount(),
            ]);
            return {
                name: queue.name,
                waiting,
                active,
                completed,
                failed,
                delayed,
            };
        })
    );
    return stats;
}
