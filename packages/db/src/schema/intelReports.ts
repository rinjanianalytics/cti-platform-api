/**
 * Intel reports — broad threat-intel narrative ingestion (RSS).
 *
 * Generalises `telco_advisories`: a raw store for security-reporting items
 * (vendor CTI blogs, CISA advisories, The DFIR Report, …) ingested from free
 * RSS/Atom. Phase 1 of the RSS + extraction work — collection only; the
 * extraction columns (`entities`, `extraction_status`, `llm_provider`) are
 * filled later (Phase 2/3) when we pull actor → technique TTPs out of these
 * into `actor_ttp_changes`. See docs/RSS-EXTRACTION-DESIGN.md.
 *
 * Idempotent upsert on `external_id` (the article URL).
 */

import { pgTable, uuid, varchar, text, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

export type IntelExtractionStatus = 'pending' | 'extracted' | 'staged' | 'committed' | 'error';

export const intelReports = pgTable('intel_reports', {
    id: uuid('id').primaryKey().defaultRandom(),
    // RSS source key, e.g. 'dfir', 'cisa', 'talos', 'unit42'.
    source: varchar('source', { length: 64 }).notNull(),
    // Natural key for idempotent upsert — the article URL.
    externalId: varchar('external_id', { length: 1024 }).notNull().unique(),
    title: text('title').notNull(),
    url: text('url').notNull(),
    summary: text('summary'),
    publishedAt: timestamp('published_at', { withTimezone: true }),
    tags: jsonb('tags').$type<string[]>().notNull().default([]),

    // --- Extraction (Phase 2/3; unused in Phase 1 collection) ---
    // {threatActors:[], techniques:[], malwareFamilies:[], …} from extractEntities().
    entities: jsonb('entities').$type<Record<string, unknown>>().notNull().default({}),
    extractionStatus: varchar('extraction_status', { length: 20 })
        .notNull().default('pending').$type<IntelExtractionStatus>(),
    llmProvider: varchar('llm_provider', { length: 50 }),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    publishedIdx: index('intel_reports_published_idx').on(table.publishedAt),
    statusIdx: index('intel_reports_status_idx').on(table.extractionStatus),
    sourceIdx: index('intel_reports_source_idx').on(table.source),
}));

export type IntelReport = typeof intelReports.$inferSelect;
export type NewIntelReport = typeof intelReports.$inferInsert;
