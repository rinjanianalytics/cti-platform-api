/**
 * On-chain entity model — AA.6.1 (PLAN Phase 8, "follow the money").
 *
 * Migration: drizzle/0065_onchain_wallets.sql
 *
 * Wallet entities for tracing telco-fraud cashout into crypto (sim-swap →
 * theft, IRSF → cashout). Mirrors the B1 telco entity template (telco.ts):
 * nullable stix_id, natural `ref_id` (= "<chain>:<address>") as the upsert key.
 *
 * PLAN INVARIANT — on-chain attribution is CONFIDENCE-WEIGHTED, NEVER asserted
 * as fact. `entity_label`/`entity_type` always travel with a `confidence`
 * (0–100) and an `attribution_source` (ofac | scamsniffer | defillama |
 * blockscout | misttrack | manual | agent). A label is
 * a claim, not a truth. The graph edges added in AA.6.2 carry confidence too.
 *
 * No external data is bundled — wallets are operator-entered or enriched via
 * the BYO-key Arkham tool (AA.6.2). No existing table is altered.
 */

import { pgTable, uuid, varchar, text, integer, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

export const wallets = pgTable('wallets', {
    id: uuid('id').primaryKey().defaultRandom(),
    // Nullable STIX id (wallets aren't STIX objects); unique when present.
    stixId: varchar('stix_id', { length: 255 }).unique(),
    // Natural key — required + unique. "<chain>:<address>", e.g. "eth:0xab…".
    refId: varchar('ref_id', { length: 255 }).notNull().unique(),
    // The raw on-chain address + its chain (kept separate from ref_id for query).
    address: varchar('address', { length: 255 }).notNull(),
    chain: varchar('chain', { length: 32 }).notNull(),                  // eth, btc, tron, …
    name: varchar('name', { length: 500 }),
    description: text('description'),
    // Attribution — who controls/operates this wallet. A CLAIM, not a fact:
    entityLabel: varchar('entity_label', { length: 255 }),             // "Lazarus Group", "Binance hot wallet"
    entityType: varchar('entity_type', { length: 64 }),                // exchange | mixer | personal | defi | sanctioned | …
    // 0–100 confidence in the attribution. Default 50 = "no strong signal".
    confidence: integer('confidence').notNull().default(50),
    attributionSource: varchar('attribution_source', { length: 64 }),  // ofac | scamsniffer | defillama | blockscout | misttrack | manual | agent
    riskTags: jsonb('risk_tags').$type<string[]>().notNull().default([]),                            // ["sanctioned","mixer"]
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    refIdIdx: index('wallets_ref_id_idx').on(table.refId),
    addressIdx: index('wallets_address_idx').on(table.address),
    chainIdx: index('wallets_chain_idx').on(table.chain),
    entityLabelIdx: index('wallets_entity_label_idx').on(table.entityLabel),
}));

export type Wallet = typeof wallets.$inferSelect;
export type NewWallet = typeof wallets.$inferInsert;
