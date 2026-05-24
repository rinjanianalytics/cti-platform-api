/**
 * Admin-editable overrides for scheduled (repeatable) BullMQ jobs.
 *
 * Code in apps/api/src/queues/scheduler.ts defines the canonical job
 * registry. This table holds optional per-job overrides — toggle
 * enabled/disabled, pick a curated interval preset, override the payload.
 * Missing row = use the code default.
 */

import { pgTable, text, boolean, jsonb, timestamp, uuid } from 'drizzle-orm/pg-core';

export const scheduledJobOverrides = pgTable('scheduled_job_overrides', {
    jobKey: text('job_key').primaryKey(),
    enabled: boolean('enabled').notNull().default(true),
    intervalPreset: text('interval_preset'),         // '15m' | '30m' | '1h' | '4h' | '6h' | 'daily' | 'weekly' | null
    payload: jsonb('payload').$type<Record<string, unknown> | null>(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    // Loose FK — a deleted admin shouldn't break the row's existence.
    updatedBy: uuid('updated_by'),
});

export type ScheduledJobOverride = typeof scheduledJobOverrides.$inferSelect;
export type NewScheduledJobOverride = typeof scheduledJobOverrides.$inferInsert;
