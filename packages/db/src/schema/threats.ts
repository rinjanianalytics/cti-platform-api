/**
 * Database Schema - Threat Intelligence
 * 
 * Tables for threat intelligence data (for local caching/sync from Rinjani).
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ============================================================================
// Threat Actors
// ============================================================================

export const threatActors = pgTable('threat_actors', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).notNull().unique(),
    // Real STIX ID from the upstream MITRE bundle (e.g. `intrusion-set--<uuid>`).
    // Distinct from the synthetic `stix_id` (`mitre--<mitreId>`) so JOINs
    // against the `relationships` table — which carries the real IDs in
    // source_id/target_id — work without breaking callers that depend on
    // the synthetic primary identifier.
    realStixId: varchar('real_stix_id', { length: 255 }),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    aliases: jsonb('aliases').$type<string[]>().default([]),
    sophistication: varchar('sophistication', { length: 50 }),
    resourceLevel: varchar('resource_level', { length: 50 }),
    primaryMotivation: varchar('primary_motivation', { length: 100 }),
    secondaryMotivations: jsonb('secondary_motivations').$type<string[]>().default([]),
    goals: jsonb('goals').$type<string[]>().default([]),
    labels: jsonb('labels').$type<string[]>().default([]),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().default([]),
    confidence: varchar('confidence', { length: 20 }),
    country: varchar('country', { length: 100 }),
    firstSeen: timestamp('first_seen', { withTimezone: true }),
    lastSeen: timestamp('last_seen', { withTimezone: true }),
    createdByRef: varchar('created_by_ref', { length: 255 }),
    objectMarkingRefs: jsonb('object_marking_refs').$type<string[]>().default([]),
    stixCreated: timestamp('stix_created', { withTimezone: true }),
    stixModified: timestamp('stix_modified', { withTimezone: true }),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    nameIdx: index('threat_actors_name_idx').on(table.name),
    stixIdIdx: index('threat_actors_stix_id_idx').on(table.stixId),
    realStixIdIdx: index('threat_actors_real_stix_id_idx').on(table.realStixId),
}));

// ============================================================================
// Indicators
// ============================================================================

export const indicators = pgTable('indicators', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).notNull().unique(),
    pattern: text('pattern').notNull(),
    patternType: varchar('pattern_type', { length: 50 }).notNull(),
    patternVersion: varchar('pattern_version', { length: 20 }),
    name: varchar('name', { length: 500 }),
    description: text('description'),
    validFrom: timestamp('valid_from', { withTimezone: true }),
    validUntil: timestamp('valid_until', { withTimezone: true }),
    labels: jsonb('labels').$type<string[]>().default([]),
    killChainPhases: jsonb('kill_chain_phases').$type<Record<string, unknown>[]>().default([]),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().default([]),
    confidence: varchar('confidence', { length: 20 }),
    createdByRef: varchar('created_by_ref', { length: 255 }),
    objectMarkingRefs: jsonb('object_marking_refs').$type<string[]>().default([]),
    stixCreated: timestamp('stix_created', { withTimezone: true }),
    stixModified: timestamp('stix_modified', { withTimezone: true }),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    patternIdx: index('indicators_pattern_idx').on(table.pattern),
    patternTypeIdx: index('indicators_pattern_type_idx').on(table.patternType),
    stixIdIdx: index('indicators_stix_id_idx').on(table.stixId),
}));

// ============================================================================
// Malware
// ============================================================================

export const malware = pgTable('malware', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).notNull().unique(),
    // Real STIX ID from upstream (`malware--<uuid>`). See threat_actors.realStixId.
    realStixId: varchar('real_stix_id', { length: 255 }),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    malwareTypes: jsonb('malware_types').$type<string[]>().default([]),
    isFamily: varchar('is_family', { length: 10 }),
    aliases: jsonb('aliases').$type<string[]>().default([]),
    capabilities: jsonb('capabilities').$type<string[]>().default([]),
    labels: jsonb('labels').$type<string[]>().default([]),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().default([]),
    stixCreated: timestamp('stix_created', { withTimezone: true }),
    stixModified: timestamp('stix_modified', { withTimezone: true }),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    nameIdx: index('malware_name_idx').on(table.name),
    stixIdIdx: index('malware_stix_id_idx').on(table.stixId),
    realStixIdIdx: index('malware_real_stix_id_idx').on(table.realStixId),
}));

// ============================================================================
// Galaxy Clusters (generic MISP Galaxy data — tools, exploit-kits, sectors, etc.)
// ============================================================================

export const galaxyClusters = pgTable('galaxy_clusters', {
    id: uuid('id').primaryKey().defaultRandom(),
    galaxyType: varchar('galaxy_type', { length: 100 }).notNull(), // tool, exploit-kit, ransomware, sector, country, etc.
    uuid: varchar('uuid', { length: 255 }).notNull().unique(),      // MISP Galaxy UUID
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    aliases: jsonb('aliases').$type<string[]>().default([]),
    meta: jsonb('meta').$type<Record<string, unknown>>().default({}), // All MISP meta fields
    labels: jsonb('labels').$type<string[]>().default([]),
    externalReferences: jsonb('external_references').$type<string[]>().default([]),
    source: varchar('source', { length: 100 }).default('misp-galaxy'),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    galaxyTypeIdx: index('galaxy_clusters_type_idx').on(table.galaxyType),
    uuidIdx: index('galaxy_clusters_uuid_idx').on(table.uuid),
    nameIdx: index('galaxy_clusters_name_idx').on(table.name),
}));

// ============================================================================
// Detection Rules (Sigma rules from MISP Galaxy)
// ============================================================================

export const detectionRules = pgTable('detection_rules', {
    id: uuid('id').primaryKey().defaultRandom(),
    ruleType: varchar('rule_type', { length: 50 }).notNull().default('sigma'), // sigma, yara, snort, etc.
    uuid: varchar('uuid', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 1000 }).notNull(),
    description: text('description'),
    severity: varchar('severity', { length: 20 }),          // critical, high, medium, low, informational
    status: varchar('status', { length: 20 }),               // stable, test, experimental, deprecated
    tags: jsonb('tags').$type<string[]>().default([]),        // MITRE ATT&CK tags, etc.
    detection: jsonb('detection').$type<Record<string, unknown>>().default({}), // Sigma detection logic
    meta: jsonb('meta').$type<Record<string, unknown>>().default({}),           // Full MISP meta
    externalReferences: jsonb('external_references').$type<string[]>().default([]),
    source: varchar('source', { length: 100 }).default('misp-galaxy'),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    ruleTypeIdx: index('detection_rules_type_idx').on(table.ruleType),
    uuidIdx: index('detection_rules_uuid_idx').on(table.uuid),
    nameIdx: index('detection_rules_name_idx').on(table.name),
    severityIdx: index('detection_rules_severity_idx').on(table.severity),
}));

// ============================================================================
// Sync Log (for tracking Rinjani sync status)
// ============================================================================

export const syncLogs = pgTable('sync_logs', {
    id: uuid('id').primaryKey().defaultRandom(),
    entityType: varchar('entity_type', { length: 100 }).notNull(),
    status: varchar('status', { length: 20 }).notNull(), // 'pending', 'success', 'failed'
    itemsProcessed: jsonb('items_processed').$type<number>().default(0),
    itemsFailed: jsonb('items_failed').$type<number>().default(0),
    lastSyncCursor: varchar('last_sync_cursor', { length: 255 }),
    errorMessage: text('error_message'),
    startedAt: timestamp('started_at', { withTimezone: true }).notNull(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});
