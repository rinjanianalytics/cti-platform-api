/**
 * Feed Manifest persistence — A2 of the declarative connector engine.
 *
 * Migration: drizzle/0059_feed_manifest.sql
 *
 * Stores the parser-definition layer that @rinjani/feed-engine runs.
 * Scheduling/credentials/URL/format live in `feeds_config` (unchanged) —
 * this table owns only the manifest body + audit + version trail.
 *
 * IMMUTABLE rows: each save creates a new version for the source. Toggling
 * is_active is the only post-insert mutation. Rollback = activate older
 * version. Parity-diff = compare two versions.
 *
 * created_by is text (not a FK to users.id): API-key auth uses
 * "key:xxxxxxxx" subjects (apps/api/src/middleware/auth.ts), not UUIDs,
 * so a FK would break that path.
 */

import { sql } from 'drizzle-orm';
import { pgTable, uuid, varchar, integer, jsonb, boolean, text, timestamp, index, uniqueIndex } from 'drizzle-orm/pg-core';

export const feedManifest = pgTable('feed_manifest', {
    id: uuid('id').primaryKey().defaultRandom(),
    source: varchar('source', { length: 100 }).notNull(),
    version: integer('version').notNull(),
    entity: varchar('entity', { length: 50 }).notNull(),
    manifest: jsonb('manifest').$type<Record<string, unknown>>().notNull(),
    isActive: boolean('is_active').notNull().default(false),
    createdBy: text('created_by').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastValidatedAt: timestamp('last_validated_at', { withTimezone: true }),
    lastValidationErrors: jsonb('last_validation_errors').$type<unknown>(),
}, (table) => ({
    sourceVersionUnique: uniqueIndex('feed_manifest_source_version_unique').on(table.source, table.version),
    // Partial unique index for "at most one active manifest per source" — see
    // 0059_feed_manifest.sql. Drizzle's index helper carries the predicate
    // through to drizzle-kit but the SQL file is authoritative for the apply
    // path; this entry is for the type-system + drizzle-studio surface.
    activePerSource: uniqueIndex('feed_manifest_active_per_source')
        .on(table.source)
        .where(sql`${table.isActive} = true`),
    sourceIdx: index('feed_manifest_source_idx').on(table.source),
    entityIdx: index('feed_manifest_entity_idx').on(table.entity),
}));

export type FeedManifestRow = typeof feedManifest.$inferSelect;
export type NewFeedManifestRow = typeof feedManifest.$inferInsert;
