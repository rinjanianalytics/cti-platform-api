/**
 * Feed sync history — per-run audit trail for upstream feed pulls.
 *
 * Created by migration `0037_feed_sync_runs.sql`. Previously lived
 * inside a runtime `CREATE TABLE IF NOT EXISTS` block in
 * `apps/api/src/services/configStore.ts`, which emitted Postgres
 * NOTICEs on every boot and kept the column set invisible to Drizzle.
 *
 * Column types match the migration. Defaults are echoed here so
 * `$inferInsert` types let callers omit them.
 */

import { pgTable, text, timestamp, integer, index } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const feedSyncRuns = pgTable('feed_sync_runs', {
    id: text('id').primaryKey().default(sql`gen_random_uuid()::text`),
    feedId: text('feed_id').notNull(),
    status: text('status').notNull().default('running'),
    startedAt: timestamp('started_at', { withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    durationMs: integer('duration_ms'),
    itemsIngested: integer('items_ingested').default(0),
    errors: integer('errors').default(0),
    errorDetails: text('error_details'),
    triggeredBy: text('triggered_by').notNull().default('scheduler'),
}, (t) => ({
    feedIdIdx: index('idx_feed_sync_runs_feed_id').on(t.feedId),
    // The physical index is DESC (see `0037_feed_sync_runs.sql`), but
    // Drizzle's `.on()` builder in this version only accepts column refs.
    // Schema declares index *existence*; the migration is authoritative on
    // ordering. Postgres can scan an ASC b-tree backwards for DESC queries
    // efficiently, so even if drift occurred the query plan is the same.
    startedAtIdx: index('idx_feed_sync_runs_started_at').on(t.startedAt),
}));

export type FeedSyncRunRow = typeof feedSyncRuns.$inferSelect;
export type NewFeedSyncRunRow = typeof feedSyncRuns.$inferInsert;
