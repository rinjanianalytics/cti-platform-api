/**
 * Audit Log Database Schema
 * 
 * Provides data provenance and versioning for all threat intelligence entities.
 * Tracks who changed what, when, and stores the previous state.
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, index, pgEnum } from 'drizzle-orm/pg-core';

// ============================================================================
// Enums
// ============================================================================

export const auditActionEnum = pgEnum('audit_action', ['create', 'update', 'delete', 'merge', 'enrich']);
export const entityTypeEnum = pgEnum('entity_type', ['ioc', 'vulnerability', 'threat_actor', 'pulse', 'indicator', 'malware', 'user']);

// ============================================================================
// Audit Log Table
// ============================================================================

export const auditLogs = pgTable('audit_logs', {
    id: uuid('id').primaryKey().defaultRandom(),

    // What was changed
    entityType: entityTypeEnum('entity_type').notNull(),
    entityId: uuid('entity_id').notNull(),

    // What happened
    action: auditActionEnum('action').notNull(),

    // Who made the change
    userId: uuid('user_id'),
    apiKeyId: uuid('api_key_id'),
    source: varchar('source', { length: 100 }), // system, api, feed-sync, manual

    // Change details
    changes: jsonb('changes').$type<{
        before?: Record<string, unknown>;
        after?: Record<string, unknown>;
        diff?: Array<{ field: string; old: unknown; new: unknown }>;
    }>(),

    // Additional context
    metadata: jsonb('metadata').$type<{
        ip?: string;
        userAgent?: string;
        requestId?: string;
        reason?: string;
    }>(),

    // Timestamps
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    entityIdx: index('audit_logs_entity_idx').on(table.entityType, table.entityId),
    actionIdx: index('audit_logs_action_idx').on(table.action),
    userIdx: index('audit_logs_user_idx').on(table.userId),
    createdAtIdx: index('audit_logs_created_at_idx').on(table.createdAt),
}));

// ============================================================================
// Data Versions (for full versioning)
// ============================================================================

export const dataVersions = pgTable('data_versions', {
    id: uuid('id').primaryKey().defaultRandom(),

    // Entity reference
    entityType: entityTypeEnum('entity_type').notNull(),
    entityId: uuid('entity_id').notNull(),

    // Version info
    versionNumber: varchar('version_number', { length: 20 }).notNull(), // semver-like

    // Full snapshot at this version
    data: jsonb('data').notNull(),

    // Hash for integrity verification
    dataHash: varchar('data_hash', { length: 64 }).notNull(),

    // Provenance
    createdBy: varchar('created_by', { length: 255 }),
    source: varchar('source', { length: 100 }),

    // Timestamps
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    entityVersionIdx: index('data_versions_entity_version_idx').on(table.entityType, table.entityId, table.versionNumber),
    hashIdx: index('data_versions_hash_idx').on(table.dataHash),
}));

// Type exports
export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
export type DataVersion = typeof dataVersions.$inferSelect;
export type NewDataVersion = typeof dataVersions.$inferInsert;
