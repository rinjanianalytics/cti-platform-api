import { emitWebhookEvent, WEBHOOK_EVENTS } from '@rinjani/core/webhooks';
import { alertsQueue, neo4jSyncQueue, cveEnrichmentQueue } from '../index';
import { feedSyncWorker, enrichmentWorker } from './feedWorkers';
import { aiAnalysisWorker, notificationWorker, alertsWorker } from './utilityWorkers';
import { neo4jSyncWorker } from './syncWorkers';
import { cveEnrichmentWorker } from './cveEnrichmentWorker';
import { retentionWorker } from './retentionWorker';
import { indexVulnerabilities, indexIOCs, indexActors } from '../../services/opensearch/indexing';
import { createLogger } from '../../lib/logger';

// ============================================================================
// Worker Event Handlers (with Webhook Integration)
// ============================================================================

const workers = [feedSyncWorker, enrichmentWorker, aiAnalysisWorker, notificationWorker, alertsWorker, neo4jSyncWorker, cveEnrichmentWorker, retentionWorker];

const evtLog = createLogger('WorkerEvents');

// Feed Sync Worker Events
feedSyncWorker.on('completed', async (job, result) => {
    evtLog.info('Feed sync completed', { jobId: job.id });

    // Emit webhook event
    await emitWebhookEvent(WEBHOOK_EVENTS.FEED_SYNC_COMPLETED, {
        jobId: job.id,
        source: job.data.source,
        indicatorsAdded: result?.indicatorsAdded,
        indicatorsProcessed: result?.indicatorsProcessed,
        processedAt: result?.processedAt,
    });

    // Create bell notification for dashboard ONLY if new IOCs were actually ingested
    const indicatorsAdded = result?.indicatorsAdded || 0;
    const indicatorsProcessed = result?.indicatorsProcessed || result?.totalIndicators || indicatorsAdded;
    const source = job.data.source;

    if (indicatorsAdded > 0) {
        const deltaMsg = `${indicatorsAdded} new IOC${indicatorsAdded > 1 ? 's' : ''} ingested (${indicatorsProcessed} processed)`;

        await alertsQueue.add(`feed-bell-${job.id}`, {
            severity: indicatorsAdded > 10 ? 'high' : 'medium',
            type: 'ioc_detected',
            title: `Feed Sync — ${source.toUpperCase()}`,
            message: deltaMsg,
            source: source,
            metadata: {
                source: source,
                indicatorsAdded,
                indicatorsProcessed,
                autoEnrichmentJobsQueued: result?.autoEnrichmentJobsQueued || 0,
            },
        });

        // ================================================================
        // AUTO-SYNC TO NEO4J + OPENSEARCH
        // ================================================================

        // IOC sources → sync pulses & IOCs to Neo4j + OpenSearch
        const iocSources = ['otx', 'abusessl', 'threatfox', 'urlhaus', 'malwarebazaar', 'openphish', 'all'];
        if (iocSources.includes(source) && indicatorsAdded > 0) {
            evtLog.info('Queueing Neo4j sync for new IOCs', { source, indicatorsAdded });
            await neo4jSyncQueue.add(
                `auto-sync-iocs-${job.id}`,
                {
                    syncType: source === 'otx' ? 'pulses-iocs' : 'all-iocs',
                    options: { maxPulses: 100, maxIOCs: Math.min(indicatorsAdded + 100, 2000) },
                },
                {
                    delay: 5000,
                    priority: 5,
                }
            );

            // OpenSearch: index IOCs as raw intelligence (vector embeddings for search)
            try {
                evtLog.info('Indexing IOCs to OpenSearch...', { source });
                const indexed = await indexIOCs();
                evtLog.info('OpenSearch IOC indexing complete', { indexed });
            } catch (osErr) {
                evtLog.error('OpenSearch IOC indexing failed', osErr as Error);
            }
        }

        // Actor sources (MITRE, MISP Galaxy) → sync to Neo4j + OpenSearch
        const actorSources = ['mitre', 'mispgalaxy'];
        if (actorSources.includes(source)) {
            evtLog.info('Queueing Neo4j sync for actors', { source });
            await neo4jSyncQueue.add(
                `auto-sync-actors-${job.id}`,
                {
                    syncType: 'actors',
                },
                {
                    delay: 5000,
                    priority: 5,
                }
            );

            // OpenSearch: index actors as raw intelligence
            try {
                evtLog.info('Indexing actors to OpenSearch...', { source });
                const indexed = await indexActors();
                evtLog.info('OpenSearch actor indexing complete', { indexed });
            } catch (osErr) {
                evtLog.error('OpenSearch actor indexing failed', osErr as Error);
            }
        }

        // CVE sources (NVD, CISA) → sync CVEs to Neo4j + OpenSearch vectors
        if (source === 'nvd' || source === 'cisa' || source === 'all') {
            evtLog.info('Queueing Neo4j CVE sync + OpenSearch indexing', { source, indicatorsAdded });

            // Neo4j: sync CVE nodes to graph
            await neo4jSyncQueue.add(
                `auto-sync-cves-${job.id}`,
                {
                    syncType: 'cves',
                    options: { maxCVEs: Math.min(indicatorsAdded + 100, 2000) },
                },
                {
                    delay: 5000,
                    priority: 5,
                }
            );

            // OpenSearch: index vulnerabilities with vector embeddings
            try {
                evtLog.info('Indexing vulnerabilities to OpenSearch...');
                const indexed = await indexVulnerabilities();
                evtLog.info('OpenSearch vulnerability indexing complete', { indexed });
            } catch (osErr) {
                evtLog.error('OpenSearch vulnerability indexing failed', osErr as Error);
            }

            // CVE Enrichment: backfill CVSS scores for CISA KEV entries
            if (source === 'cisa' || source === 'all') {
                evtLog.info('Queueing CVE enrichment (CVSS backfill) after CISA sync');
                await cveEnrichmentQueue.add(
                    `auto-enrich-cves-${job.id}`,
                    { type: 'all', batchSize: 100 },
                    { delay: 30000, priority: 5 },
                );
            }
        }
    } else if (indicatorsProcessed > 0) {
        // No new IOCs — just log it, don't spam the notification bell
        evtLog.info('Feed sync completed, no new indicators', { source, indicatorsProcessed });
    }
});

feedSyncWorker.on('failed', async (job, err) => {
    const isPermanent = job && job.attemptsMade >= (job.opts?.attempts || 3);

    await emitWebhookEvent(WEBHOOK_EVENTS.FEED_SYNC_FAILED, {
        jobId: job?.id,
        source: job?.data.source,
        error: err.message,
        isPermanent,
        attemptsMade: job?.attemptsMade,
    });

    // Create alert only for permanent failures
    if (isPermanent) {
        await alertsQueue.add(`feed-fail-${job?.id}`, {
            severity: 'high',
            type: 'system_error',
            title: `Feed Sync Failed — ${job?.data.source?.toUpperCase()}`,
            message: `Feed sync permanently failed after ${job?.attemptsMade} attempts: ${err.message}`,
            source: job?.data.source || 'unknown',
            metadata: { error: err.message, attempts: job?.attemptsMade },
        });
    }

    // Dead-letter queue logging for permanently failed jobs
    if (isPermanent) {
        evtLog.error('Feed sync permanently failed — moved to DLQ', err, { jobId: job?.id, attempts: job?.attemptsMade });
    }
});

// Enrichment Worker Events
enrichmentWorker.on('completed', async (job, result) => {
    evtLog.info('Enrichment completed', { jobId: job.id });
    await emitWebhookEvent('ioc.enriched', {
        jobId: job.id,
        iocId: job.data.iocId,
        iocValue: job.data.iocValue,
        iocType: job.data.iocType,
        riskLevel: result?.riskLevel,
        riskScore: result?.riskScore,
        enrichmentCount: result?.enrichmentCount,
    });

    // Emit high-severity alert if risk is high/critical
    if (result?.riskLevel === 'high' || result?.riskLevel === 'critical') {
        await emitWebhookEvent(WEBHOOK_EVENTS.ALERT_HIGH_SEVERITY, {
            type: 'enrichment',
            severity: result.riskLevel,
            iocValue: job.data.iocValue,
            iocType: job.data.iocType,
            riskScore: result.riskScore,
        });
    }
});

// AI Analysis Worker Events  
aiAnalysisWorker.on('completed', async (job, result) => {
    evtLog.info('AI analysis completed', { jobId: job.id });
    await emitWebhookEvent('ai.analysis_completed', {
        jobId: job.id,
        iocId: job.data.iocId,
        iocValue: job.data.iocValue,
        analysisType: job.data.analysisType,
        provider: result?.provider,
    });
});

// Neo4j Sync Worker Events
neo4jSyncWorker.on('completed', async (job, result) => {
    evtLog.info('Neo4j sync completed', { jobId: job.id, syncType: job.data.syncType });
});

neo4jSyncWorker.on('failed', async (job, err) => {
    evtLog.error('Neo4j sync failed', err, { jobId: job?.id });
});

// General error handler for all workers
workers.forEach((worker) => {
    worker.on('error', (err) => {
        evtLog.error('Worker error', err, { worker: worker.name });
    });
});

// ============================================================================
// Startup & Shutdown
// ============================================================================

const startupLog = createLogger('Workers');

/**
 * Start all workers
 */
export function startWorkers() {
    startupLog.info('Starting all BullMQ workers', { workers: workers.map(w => w.name) });
}

/**
 * Graceful shutdown
 */
export async function stopWorkers() {
    startupLog.info('Stopping all workers...');
    await Promise.all(workers.map(w => w.close()));
    startupLog.info('All workers stopped');
}
