/**
 * AI Incident model — the AI-threat-landscape vertical.
 *
 * Migration: drizzle/0067_ai_incidents.sql
 *
 * Real-world AI harm/failure incidents ingested from the AI Incident Database
 * (incidentdatabase.ai) — the live "what's actually going wrong with deployed
 * AI" signal that complements the static MITRE ATLAS technique taxonomy.
 *
 * DELIBERATELY a dedicated table, NOT atlas_case_studies: ATLAS case studies
 * are ~30 curated incidents mapped to AML techniques; AID is ~1500 raw
 * incidents with no technique mapping. Mixing them would distort the ATLAS
 * coverage heatmap. This mirrors the per-domain entity pattern — telco
 * (telco.ts) and on-chain (onchain.ts) each own their tables.
 *
 * Natural key: `incident_id` (AID's stable integer id) — the upsert target.
 * `tags` is derived at ingest (always includes `ai-incident` + entity slugs)
 * so the AI vertical can contribute a trend signal the same way IOC tags do.
 */

import { pgTable, uuid, varchar, text, integer, jsonb, date, timestamp, index } from 'drizzle-orm/pg-core';

export const aiIncidents = pgTable('ai_incidents', {
    id: uuid('id').primaryKey().defaultRandom(),
    // AID's stable integer incident id — required + unique (the upsert key).
    incidentId: integer('incident_id').notNull().unique(),
    title: text('title').notNull(),
    description: text('description'),
    // Incident date as reported by AID (YYYY-MM-DD). Real date column so the
    // "incidents over time" trend can ORDER BY / bucket by interval.
    incidentDate: date('incident_date'),
    // Alleged parties (entity slugs, e.g. "uber", "openai"). Claims, per AID.
    deployers: jsonb('deployers').$type<string[]>().notNull().default([]),
    developers: jsonb('developers').$type<string[]>().notNull().default([]),
    harmedParties: jsonb('harmed_parties').$type<string[]>().notNull().default([]),
    // Linked AID report numbers + a denormalized count (corroboration weight).
    reportIds: jsonb('report_ids').$type<number[]>().notNull().default([]),
    reportCount: integer('report_count').notNull().default(0),
    // Derived at ingest — always includes `ai-incident` plus entity slugs.
    tags: jsonb('tags').$type<string[]>().notNull().default([]),
    url: varchar('url', { length: 512 }),               // https://incidentdatabase.ai/cite/<id>
    source: varchar('source', { length: 32 }).notNull().default('aiid'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    incidentIdIdx: index('ai_incidents_incident_id_idx').on(table.incidentId),
    incidentDateIdx: index('ai_incidents_incident_date_idx').on(table.incidentDate),
    sourceIdx: index('ai_incidents_source_idx').on(table.source),
}));

export type AiIncident = typeof aiIncidents.$inferSelect;
export type NewAiIncident = typeof aiIncidents.$inferInsert;
