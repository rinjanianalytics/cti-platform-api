/**
 * Audit Logging Service
 *
 * Provides automated audit trail for all entity mutations.
 * Used by both the audit middleware (auto-capture from API routes)
 * and direct calls from stream consumers / background workers.
 */

import { db } from '@rinjani/db';
import { auditLogs, auditActionEnum, entityTypeEnum } from '@rinjani/db/schema';
import type { NewAuditLog } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('AuditService');

// The Drizzle pgEnum is the single source of truth — TS allow-lists and
// types derive from `.enumValues`. Adding a new audit-action or entity-type
// happens in exactly one place (schema/audit.ts + a migration) and
// auto-propagates here. We previously hit silent insert-failures when this
// list drifted from the DB enum; deriving prevents that class of bug.
const VALID_ENTITY_TYPES = entityTypeEnum.enumValues;
const VALID_ACTIONS = auditActionEnum.enumValues;

type EntityType = typeof entityTypeEnum.enumValues[number];
type AuditAction = typeof auditActionEnum.enumValues[number];

export interface AuditLogInput {
    entityType: EntityType;
    entityId: string;
    action: AuditAction;
    userId?: string;
    apiKeyId?: string;
    source?: string;
    changes?: {
        before?: Record<string, unknown>;
        after?: Record<string, unknown>;
        diff?: Array<{ field: string; old: unknown; new: unknown }>;
    };
    metadata?: {
        ip?: string;
        userAgent?: string;
        requestId?: string;
        reason?: string;
        [key: string]: unknown;
    };
}

/**
 * Write a single audit log entry.
 * Fire-and-forget by default — never throws to avoid disrupting the main flow.
 */
export async function logAudit(input: AuditLogInput): Promise<void> {
    try {
        // Validate entity type and action
        if (!VALID_ENTITY_TYPES.includes(input.entityType)) {
            log.debug('Skipping audit: invalid entity type', { entityType: input.entityType });
            return;
        }
        if (!VALID_ACTIONS.includes(input.action)) {
            log.debug('Skipping audit: invalid action', { action: input.action });
            return;
        }

        await db.insert(auditLogs).values({
            entityType: input.entityType,
            entityId: input.entityId,
            action: input.action,
            userId: input.userId || null,
            apiKeyId: input.apiKeyId || null,
            source: input.source || 'system',
            changes: input.changes || null,
            metadata: input.metadata || null,
        } as NewAuditLog);
    } catch (err) {
        // Never throw — audit logging must not disrupt main flow
        log.warn('Failed to write audit log', {
            entityType: input.entityType,
            action: input.action,
            error: (err as Error).message,
        });
    }
}

/**
 * Write multiple audit entries in a single batch INSERT.
 * Used by feed-sync and bulk operations.
 */
export async function logAuditBatch(entries: AuditLogInput[]): Promise<void> {
    if (entries.length === 0) return;

    try {
        const values = entries
            .filter(e => VALID_ENTITY_TYPES.includes(e.entityType) && VALID_ACTIONS.includes(e.action))
            .map(e => ({
                entityType: e.entityType,
                entityId: e.entityId,
                action: e.action,
                userId: e.userId || null,
                apiKeyId: e.apiKeyId || null,
                source: e.source || 'system',
                changes: e.changes || null,
                metadata: e.metadata || null,
            } as NewAuditLog));

        if (values.length > 0) {
            await db.insert(auditLogs).values(values);
        }
    } catch (err) {
        log.warn('Failed to write audit batch', {
            count: entries.length,
            error: (err as Error).message,
        });
    }
}

// ============================================================================
// Route-path → entity type mapping
// ============================================================================

const PATH_ENTITY_MAP: Record<string, EntityType> = {
    'iocs': 'ioc',
    'indicators': 'indicator',
    'vulnerabilities': 'vulnerability',
    'threats': 'threat_actor',
    'threat-actors': 'threat_actor',
    'pulses': 'pulse',
    'malware': 'malware',
};

const METHOD_ACTION_MAP: Record<string, AuditAction> = {
    'POST': 'create',
    'PUT': 'update',
    'PATCH': 'update',
    'DELETE': 'delete',
};

/**
 * Infer entity type from the URL path.
 * Matches /v1/{resource}/... patterns.
 */
export function inferEntityType(path: string): EntityType | null {
    // Try matching /v1/{resource} or /{resource}
    const match = path.match(/\/(?:v[12]\/)?([a-z-]+)/);
    if (match) {
        return PATH_ENTITY_MAP[match[1]] || null;
    }
    return null;
}

/**
 * Extract entity ID from the response body or URL path.
 */
export function extractEntityId(path: string, body: Record<string, unknown> | null): string | null {
    // From response body (most APIs return { data: { id: ... } } or { id: ... })
    if (body) {
        const data = (body.data || body) as Record<string, unknown>;
        if (data.id && typeof data.id === 'string') return data.id;
        if (data.entityId && typeof data.entityId === 'string') return data.entityId;
    }

    // From URL path: /v1/iocs/:id
    const pathMatch = path.match(/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i);
    if (pathMatch) return pathMatch[1];

    return null;
}

/**
 * Infer action from HTTP method.
 */
export function inferAction(method: string): AuditAction {
    return METHOD_ACTION_MAP[method.toUpperCase()] || 'update';
}
