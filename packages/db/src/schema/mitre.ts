/**
 * MITRE ATT&CK Database Schema
 * 
 * Tables for storing ATT&CK framework data:
 * - tactics: ATT&CK Tactics (TA0001-TA0043)
 * - techniques: ATT&CK Techniques (T1001-T1999)
 * - tools: Adversary tools (S0001+)
 * - relationships: Entity relationships (uses, targets, etc.)
 * 
 * NOTE: threat_actors and malware tables are defined in threats.ts
 * and enhanced with MITRE IDs via the sync process.
 */

import { pgTable, uuid, varchar, text, boolean, timestamp, jsonb, integer, unique } from 'drizzle-orm/pg-core';

// ============================================================================
// Tactics (TA0001 - Initial Access, etc.)
// ============================================================================

export const tactics = pgTable('tactics', {
    id: uuid('id').defaultRandom().primaryKey(),
    mitreId: varchar('mitre_id', { length: 20 }).notNull().unique(),  // TA0001
    name: varchar('name', { length: 256 }).notNull(),                   // Initial Access
    description: text('description'),
    shortName: varchar('short_name', { length: 64 }),                   // initial-access
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// Techniques/Sub-techniques (T1059, T1059.001, etc.)
// ============================================================================

export const techniques = pgTable('techniques', {
    id: uuid('id').defaultRandom().primaryKey(),
    mitreId: varchar('mitre_id', { length: 20 }).notNull().unique(),  // T1059.001
    // Real STIX ID from the upstream MITRE bundle, `attack-pattern--<uuid>`.
    // Needed so JOINs against the `relationships` table (which stores the
    // real STIX ID in target_id for technique edges) can resolve a
    // mitre_id / name pair without a second round-trip.
    realStixId: varchar('real_stix_id', { length: 255 }),
    name: varchar('name', { length: 256 }).notNull(),                   // PowerShell
    description: text('description'),
    detection: text('detection'),
    platforms: jsonb('platforms').$type<string[]>(),                    // ["Windows", "Linux"]
    permissions: jsonb('permissions').$type<string[]>(),                // ["User", "Administrator"]
    dataSources: jsonb('data_sources').$type<string[]>(),
    isSubtechnique: boolean('is_subtechnique').default(false),
    parentId: varchar('parent_id', { length: 20 }),                     // T1059 for sub-techniques
    tacticIds: jsonb('tactic_ids').$type<string[]>(),                   // ["TA0002", "TA0003"]
    url: varchar('url', { length: 512 }),
    version: varchar('version', { length: 20 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// Tools (Adversary tools like Mimikatz)
// ============================================================================

export const mitreTools = pgTable('tools', {
    id: uuid('id').defaultRandom().primaryKey(),
    mitreId: varchar('mitre_id', { length: 64 }).unique(),              // S0002
    name: varchar('name', { length: 256 }).notNull(),                   // Mimikatz
    aliases: jsonb('aliases').$type<string[]>(),
    description: text('description'),
    type: varchar('type', { length: 64 }),                              // credential-access
    platforms: jsonb('platforms').$type<string[]>(),
    techniqueIds: jsonb('technique_ids').$type<string[]>(),
    url: varchar('url', { length: 512 }),
    source: varchar('source', { length: 64 }).default('mitre'),
    rawData: jsonb('raw_data'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// Entity Relationships (for linking CTI entities)
// ============================================================================

export const mitreRelationships = pgTable('relationships', {
    id: uuid('id').defaultRandom().primaryKey(),
    sourceType: varchar('source_type', { length: 64 }).notNull(),       // threat_actor, malware, technique
    sourceId: varchar('source_id', { length: 128 }).notNull(),          // G0016
    relationshipType: varchar('relationship_type', { length: 64 }).notNull(), // uses, targets, attributed-to
    targetType: varchar('target_type', { length: 64 }).notNull(),       // technique, malware, sector
    targetId: varchar('target_id', { length: 128 }).notNull(),          // T1059
    description: text('description'),
    confidence: integer('confidence'),                                   // 0-100
    firstSeen: timestamp('first_seen'),
    lastSeen: timestamp('last_seen'),
    source: varchar('source', { length: 64 }).default('mitre'),
    rawData: jsonb('raw_data'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (t) => ({
    // Natural key — a relationship is identified by these five columns. The
    // user-facing POST /v1/relationships upsert relies on ON CONFLICT against
    // this constraint; without it every insert through that route fails.
    // (migration 0063_relationships_natural_key_unique.sql)
    naturalKey: unique('relationships_natural_key_unique')
        .on(t.sourceType, t.sourceId, t.targetType, t.targetId, t.relationshipType),
}));

// Re-export threatActors and malware from threats.ts - they already exist
// import { threatActors, malware } from './threats';
// export { threatActors, malware };
