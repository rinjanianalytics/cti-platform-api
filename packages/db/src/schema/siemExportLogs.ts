/**
 * SIEM export / push audit — the funnel's "Actioned" provenance.
 *
 * Migration: drizzle/0069_siem_export_logs.sql
 *
 * One row per SIEM export or direct push (CEF/LEEF/ECS download, or Splunk HEC /
 * Elastic _bulk push). Previously these routes shipped data but recorded nothing,
 * so the signal funnel's payoff step ("Actioned · pushed to SIEM") had no source.
 * `channel='push'` rows are the disruptive actions counted by the funnel.
 */
import { pgTable, uuid, varchar, text, integer, timestamp, index } from 'drizzle-orm/pg-core';

export type SiemExportFormat = 'cef' | 'leef' | 'ecs' | 'splunk' | 'elastic';
export type SiemExportChannel = 'export' | 'push';
export type SiemExportStatus = 'success' | 'failed';

export const siemExportLogs = pgTable('siem_export_logs', {
    id: uuid('id').primaryKey().defaultRandom(),
    format: varchar('format', { length: 20 }).notNull().$type<SiemExportFormat>(),
    // 'export' = file download (CEF/LEEF/ECS); 'push' = direct ship to a SIEM.
    channel: varchar('channel', { length: 20 }).notNull().default('export').$type<SiemExportChannel>(),
    destination: text('destination'),            // HEC URL / index for pushes; null for downloads
    recordCount: integer('record_count').notNull().default(0),
    status: varchar('status', { length: 20 }).notNull().default('success').$type<SiemExportStatus>(),
    userId: text('user_id'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
    createdAtIdx: index('siem_export_logs_created_at_idx').on(t.createdAt),
    channelIdx: index('siem_export_logs_channel_idx').on(t.channel),
}));

export type SiemExportLogRow = typeof siemExportLogs.$inferSelect;
export type NewSiemExportLogRow = typeof siemExportLogs.$inferInsert;
