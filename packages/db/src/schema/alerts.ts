/**
 * Alerts — durable triage queue (replaces the in-memory alertStore).
 *
 * Migration: drizzle/0070_alerts.sql
 *
 * Previously alerts lived in a process-local array (utilityWorkers.ts) that reset
 * on every API restart and could only filter by severity/unread. This table makes
 * them durable and server-side-filterable (severity / source / type / read). The
 * row shape is a superset of the old in-memory object, so existing clients are
 * unaffected.
 *
 * `id` is text (not uuid) — the alerts worker uses the BullMQ job id as the alert
 * id, which isn't always a UUID.
 */
import { pgTable, text, varchar, boolean, jsonb, timestamp, index } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const alerts = pgTable('alerts', {
    id: text('id').primaryKey().default(sql`gen_random_uuid()::text`),
    severity: varchar('severity', { length: 20 }).notNull(),
    type: varchar('type', { length: 60 }).notNull(),
    title: text('title').notNull(),
    message: text('message').notNull(),
    source: text('source'),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().notNull().default({}),
    read: boolean('read').notNull().default(false),
    acknowledged: boolean('acknowledged').notNull().default(false),
    acknowledgedAt: timestamp('acknowledged_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
    createdAtIdx: index('alerts_created_at_idx').on(t.createdAt),
    severityIdx: index('alerts_severity_idx').on(t.severity),
    readIdx: index('alerts_read_idx').on(t.read),
    sourceIdx: index('alerts_source_idx').on(t.source),
    typeIdx: index('alerts_type_idx').on(t.type),
}));

export type AlertRow = typeof alerts.$inferSelect;
export type NewAlertRow = typeof alerts.$inferInsert;
