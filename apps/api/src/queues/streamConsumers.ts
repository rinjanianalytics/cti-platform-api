/**
 * Stream Consumer Handlers
 *
 * Each handler function is a consumer that processes events from
 * Redis Streams. They are registered as consumer groups at startup.
 *
 * Consumer Groups:
 *   enrichment-group  → Auto-triggers IOC enrichment on ioc.created
 *   opensearch-group  → Syncs entities to OpenSearch on any mutation
 *   neo4j-group       → Syncs relationships to Neo4j graph
 *   alert-group       → Evaluates alert rules on new high-risk IOCs
 *   taxii-group       → Marks entities for TAXII collection export
 *   meili-group       → Indexes searchable documents in Meilisearch
 */

import type { StreamEvent } from '../services/eventStream';
import { createLogger } from '../lib/logger';
import { escSql } from '../lib/sanitize';

const log = createLogger('StreamConsumers');

// ============================================================================
// Enrichment Consumer — auto-enrich newly created IOCs
// ============================================================================

export async function handleEnrichment(event: StreamEvent): Promise<void> {
    if (event.stream !== 'ioc' || event.action !== 'created') return;

    const { enrichmentQueue } = await import('../queues/definitions');
    const iocId = event.entityId;
    const value = (event.data.value as string) || '';
    const type = (event.data.type as string) || 'unknown';

    await enrichmentQueue.add(`stream-enrich-${iocId}`, {
        iocId,
        iocValue: value,
        iocType: type,
        priority: (event.data.riskScore as number) >= 70 ? 'high' : 'normal',
    }, {
        priority: (event.data.riskScore as number) >= 70 ? 1 : 5,
        jobId: `stream-enrich-${iocId}`, // Deduplicate
    });

    // ── YARA Auto-Tagging ───────────────────────────────────────────
    try {
        const { scanValue } = await import('../services/yaraEngine');
        const yaraResult = scanValue(value);

        if (yaraResult.matchedRules > 0) {
            const { db, sql } = await import('@rinjani/db');
            const matchedTags = yaraResult.matches.flatMap(m => m.tags);
            const uniqueTags = [...new Set(matchedTags)];

            if (uniqueTags.length > 0) {
                const tagsSql = uniqueTags.map(t => `'${escSql(t)}'`).join(',');
                await db.execute(sql.raw(
                    `UPDATE iocs SET tags = array_cat(COALESCE(tags, ARRAY[]::text[]), ARRAY[${tagsSql}]), updated_at = NOW()
                     WHERE id = '${escSql(iocId)}'`
                ));
                log.debug('YARA auto-tagged', { iocId, tags: uniqueTags, rules: yaraResult.matches.map(m => m.rule) });
            }
        }
    } catch (err) {
        log.warn('YARA auto-tag failed', { iocId, error: (err as Error).message });
    }

    // ── Composite Scoring ───────────────────────────────────────────
    try {
        const { computeCompositeScore } = await import('../services/scoringEngine');
        const score = await computeCompositeScore(iocId);

        const { db, sql } = await import('@rinjani/db');
        await db.execute(sql.raw(
            `UPDATE iocs SET risk_score = ${score.composite}, updated_at = NOW()
             WHERE id = '${escSql(iocId)}'`
        ));
        log.debug('Composite score computed', { iocId, composite: score.composite });
    } catch (err) {
        log.warn('Composite scoring failed', { iocId, error: (err as Error).message });
    }

    log.debug('Queued auto-enrichment', { iocId, type, value: value.slice(0, 40) });
}


// ============================================================================
// OpenSearch Sync Consumer — keep search index current
// ============================================================================

export async function handleOpenSearchSync(event: StreamEvent): Promise<void> {
    // Only sync mutations (created/updated/deleted/enriched)
    if (!['created', 'updated', 'deleted', 'completed'].includes(event.action)) return;

    try {
        const { getOpenSearch } = await import('../lib/db/clients');
        const osClient = await getOpenSearch();
        const index = resolveIndex(event.entityType);

        if (event.action === 'deleted') {
            await osClient.delete({ index, id: event.entityId }).catch(() => { });
            log.debug('OpenSearch delete', { index, id: event.entityId });
        } else {
            // Upsert — use the event data as partial document
            await osClient.update({
                index,
                id: event.entityId,
                body: {
                    doc: {
                        ...event.data,
                        _lastSynced: event.timestamp,
                    },
                    doc_as_upsert: true,
                },
            });
            log.debug('OpenSearch upsert', { index, id: event.entityId, action: event.action });
        }
    } catch (err) {
        log.warn('OpenSearch sync failed', { entityId: event.entityId, error: (err as Error).message });
        throw err; // Rethrow so XACK is not sent — message will be retried
    }
}

// ============================================================================
// Neo4j Sync Consumer — update graph relationships
// ============================================================================

export async function handleNeo4jSync(event: StreamEvent): Promise<void> {
    // Only handle entity mutations
    if (!['created', 'updated', 'discovered'].includes(event.action)) return;

    try {
        const { neo4jSyncQueue } = await import('../queues/definitions');

        await neo4jSyncQueue.add(`stream-neo4j-${event.entityId}`, {
            entityId: event.entityId,
            entityType: event.entityType,
            action: event.action,
            data: event.data,
        }, {
            jobId: `stream-neo4j-${event.entityId}-${event.action}`,
        });

        log.debug('Queued Neo4j sync', { entityId: event.entityId, entityType: event.entityType });
    } catch (err) {
        log.warn('Neo4j sync queue failed', { error: (err as Error).message });
        throw err;
    }
}

// ============================================================================
// Alert Consumer — evaluate alert rules for high-risk entities
// ============================================================================

export async function handleAlertEvaluation(event: StreamEvent): Promise<void> {
    // Only trigger alerts for new IOCs and completed enrichments
    if (event.stream === 'ioc' && event.action !== 'created') return;
    if (event.stream === 'enrichment' && event.action !== 'completed') return;
    if (event.stream !== 'ioc' && event.stream !== 'enrichment') return;

    const riskScore = (event.data.riskScore as number) || 0;

    // Only alert on medium-risk and above
    if (riskScore < 40) return;

    try {
        const { alertsQueue } = await import('../queues/definitions');

        const severity = riskScore >= 85 ? 'critical'
            : riskScore >= 65 ? 'high'
                : riskScore >= 40 ? 'medium'
                    : 'low';

        await alertsQueue.add(`stream-alert-${event.entityId}`, {
            severity,
            type: 'ioc_detected',
            title: `${severity.toUpperCase()}: New ${event.entityType} detected`,
            message: `${event.entityType} ${event.data.value || event.entityId} scored ${riskScore}/100`,
            source: event.source,
            metadata: {
                entityId: event.entityId,
                entityType: event.entityType,
                riskScore,
                action: event.action,
            },
        });

        log.debug('Alert queued', { entityId: event.entityId, severity, riskScore });

        // Broadcast email/Slack notifications for critical and high-severity alerts
        if (severity === 'critical' || severity === 'high') {
            try {
                const { broadcastNotification, createAlertPayload } = await import('../services/notifications');
                const payload = createAlertPayload('ioc', severity, {
                    value: (event.data.value as string) || event.entityId,
                });
                payload.data = { riskScore, entityId: event.entityId, source: event.source };
                const result = await broadcastNotification(payload);
                log.debug('Notifications sent', { entityId: event.entityId, sent: result.sent, failed: result.failed });
            } catch (notifyErr) {
                log.warn('Notification broadcast failed', { error: (notifyErr as Error).message });
            }
        }
    } catch (err) {
        log.warn('Alert evaluation failed', { error: (err as Error).message });
    }
}

// ============================================================================
// TAXII Publisher Consumer — mark entities for TAXII collection export
// ============================================================================

export async function handleTaxiiPublish(event: StreamEvent): Promise<void> {
    // Publish IOCs and actors to TAXII upon creation/enrichment
    if (!['created', 'completed'].includes(event.action)) return;
    if (!['ioc', 'actor', 'enrichment'].includes(event.stream)) return;

    // TAXII publishing is a lightweight operation — just mark in Redis
    try {
        const { getCacheConnection } = await import('../services/redis');
        const redis = getCacheConnection();

        // Add to TAXII pending set with a score of the timestamp for ordering
        const score = new Date(event.timestamp).getTime();
        await redis.zadd('rjn:taxii:pending', String(score), JSON.stringify({
            entityId: event.entityId,
            entityType: event.entityType,
            action: event.action,
        }));

        // Trim old entries (keep last 10k)
        await redis.zremrangebyrank('rjn:taxii:pending', 0, -10001);

        log.debug('TAXII export queued', { entityId: event.entityId });
    } catch (err) {
        log.warn('TAXII publish failed', { error: (err as Error).message });
    }
}

// ============================================================================
// Audit Consumer — auto-log all entity events to audit_logs table
// ============================================================================

const STREAM_TO_ENTITY: Record<string, string> = {
    'indicator': 'ioc',
    'vulnerability': 'vulnerability',
    'threat-actor': 'threat_actor',
    'threat_actor': 'threat_actor',
    'enrichment': 'ioc',
    'ioc': 'ioc',
    'malware': 'malware',
    'pulse': 'pulse',
};

const STREAM_ACTION_MAP: Record<string, string> = {
    'created': 'create',
    'updated': 'update',
    'deleted': 'delete',
    'discovered': 'create',
    'completed': 'enrich',
    'merged': 'merge',
};

export async function handleAuditLog(event: StreamEvent): Promise<void> {
    try {
        const { logAudit } = await import('../services/auditService');

        const entityType = STREAM_TO_ENTITY[event.entityType] || STREAM_TO_ENTITY[event.stream];
        if (!entityType) return;

        const action = STREAM_ACTION_MAP[event.action];
        if (!action) return;

        await logAudit({
            entityType: entityType as 'ioc' | 'vulnerability' | 'threat_actor' | 'pulse' | 'indicator' | 'malware',
            entityId: event.entityId,
            action: action as 'create' | 'update' | 'delete' | 'merge' | 'enrich',
            source: event.source || 'stream-consumer',
            changes: event.data ? { after: event.data } : undefined,
            metadata: { requestId: `stream:${event.stream}:${event.action}` },
        });
    } catch (err) {
        // Never throw for audit — it must not disrupt the stream
        log.debug('Audit log from stream failed', { error: (err as Error).message });
    }
}

// ============================================================================
// Helpers
// ============================================================================

function resolveIndex(entityType: string): string {
    switch (entityType) {
        case 'indicator': return 'iocs';
        case 'vulnerability': return 'vulnerabilities';
        case 'threat-actor': return 'threat_actors';
        case 'enrichment': return 'iocs'; // Enrichment updates the IOC index
        default: return 'iocs';
    }
}
