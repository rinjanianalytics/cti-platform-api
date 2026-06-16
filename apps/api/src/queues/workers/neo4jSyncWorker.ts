/**
 * Neo4j Graph Sync Worker
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import type { Neo4jSyncJobData } from '../types';
import {
    syncAllToNeo4j, syncActors, syncTactics, syncTechniques,
    syncMalware, syncTools, syncRelationships, syncGenericRelationships, syncPulsesAndIOCs, syncCVEs,
    syncSimilarIOCs, syncAllIOCs, syncTelco, syncWallets,
} from '../../services/neo4j';
import type { Neo4jSyncResult } from '../../services/neo4j';
import { createLogger } from '../../lib/logger';
import { getConfig } from '../../services/configStore';
import { runJobWithSpan } from '../tracing';

export const neo4jSyncWorker = new Worker<Neo4jSyncJobData>(
    'neo4j-sync',
    async (job: Job<Neo4jSyncJobData>) => runJobWithSpan('neo4j-sync', job, async () => {
        const log = createLogger('Neo4j:Sync');

        // Check if Neo4j sync is disabled via dashboard toggle
        const enabled = await getConfig('NEO4J_SYNC_ENABLED');
        if (enabled === 'false') {
            log.info('Neo4j sync disabled via settings, skipping', { jobId: job.id, syncType: job.data.syncType });
            return { skipped: true, reason: 'Neo4j sync disabled via settings' };
        }

        log.info('Processing job', { jobId: job.id, syncType: job.data.syncType });

        const { syncType, options } = job.data;

        try {
            await job.updateProgress(5);

            let result: Record<string, number>;

            switch (syncType) {
                case 'full':
                    result = await syncAllToNeo4j((pct) => job.updateProgress(pct)) as unknown as Record<string, number>;
                    break;
                case 'actors':
                    result = { actors: await syncActors() };
                    break;
                case 'techniques':
                    result = { techniques: await syncTechniques() };
                    break;
                case 'malware':
                    result = { malware: await syncMalware() };
                    break;
                case 'tools':
                    result = { tools: await syncTools() };
                    break;
                case 'relationships':
                    // Both passes: USES (MITRE UUID→ID) + every other graph edge
                    // (telco, STIX SDO links) so a relationships-only sync is complete.
                    result = {
                        relationships: await syncRelationships(),
                        genericRelationships: await syncGenericRelationships(),
                    };
                    break;
                case 'telco':
                    result = await syncTelco();
                    break;
                case 'onchain':
                    result = { wallets: await syncWallets() };
                    break;
                case 'pulses-iocs':
                    result = await syncPulsesAndIOCs(
                        options?.maxPulses || 500,
                        50,
                    );
                    break;
                case 'all-iocs':
                    result = {
                        iocs: await syncAllIOCs(
                            options?.batchSize || 5000,
                            (pct, processed, total) => {
                                job.updateProgress(pct);
                                log.info('Syncing IOCs', { processed, total, pct });
                            }
                        )
                    };
                    break;
                case 'cves':
                    result = { cves: await syncCVEs(options?.maxCVEs || 500) };
                    break;
                case 'similarity':
                    result = {
                        similarityEdges: await syncSimilarIOCs(
                            options?.maxIOCs || 500,
                            options?.minScore || 0.75,
                            options?.topK || 5,
                        )
                    };
                    break;
                default:
                    throw new Error(`Unknown sync type: ${syncType}`);
            }

            await job.updateProgress(100);

            return {
                success: true,
                syncType,
                completedAt: new Date().toISOString(),
                ...result,
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    }),
    {
        connection,
        concurrency: 1,
    }
);
