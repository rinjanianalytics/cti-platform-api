/**
 * BullMQ Queue Events (for monitoring)
 */

import { QueueEvents } from 'bullmq';
import { connection } from '../services/redis';

export const feedSyncEvents = new QueueEvents('feed-sync', { connection });
export const enrichmentEvents = new QueueEvents('ioc-enrichment', { connection });
export const aiAnalysisEvents = new QueueEvents('ai-analysis', { connection });
export const notificationEvents = new QueueEvents('notifications', { connection });
export const alertsEvents = new QueueEvents('alerts', { connection });
export const neo4jSyncEvents = new QueueEvents('neo4j-sync', { connection });
export const cveEnrichmentEvents = new QueueEvents('cve-enrichment', { connection });
export const maintenanceEvents = new QueueEvents('maintenance', { connection });
