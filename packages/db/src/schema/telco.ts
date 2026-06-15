/**
 * Telco threat-domain entities — B1.1 of the Telco vertical.
 *
 * Migration: drizzle/0060_telco_entities.sql
 *
 * Three new ENTITY tables. The 5G THREAT model already lives in `fight.ts`
 * (MITRE FiGHT — tactics/techniques/mitigations incl. the TA5001 Fraud tactic);
 * B1 does NOT rebuild it. These tables add the network-element / signaling /
 * fraud-scheme ENTITY layer that FiGHT lacks, and (in B1.2) bridge to FiGHT
 * via the `relationships` table.
 *
 * Column shape mirrors the Phase-2 STIX SDO template (stixEntities.ts /
 * migration 0046) — except:
 *   - `stix_id` is NULLABLE: telco entities aren't STIX objects, so we don't
 *     force a synthetic STIX id. Unique when present (Postgres allows many
 *     NULLs under a unique index).
 *   - `ref_id` is the natural key: NOT NULL + UNIQUE per table, used for
 *     idempotent operator upserts (vendor+model+segment, protocol+ref-point,
 *     scheme-type+slug).
 *
 * No existing SDO table is altered (PLAN invariant).
 */

import { pgTable, uuid, varchar, text, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

// ============================================================================
// Network elements — 4G/5G network functions (HSS, UDM, AMF, MME, OCS, PCRF…)
// ============================================================================

export const networkElements = pgTable('network_elements', {
    id: uuid('id').primaryKey().defaultRandom(),
    // Nullable STIX id (telco entities aren't STIX); unique when present.
    stixId: varchar('stix_id', { length: 255 }).unique(),
    // Natural key — required + unique. e.g. "ericsson:hss:core".
    refId: varchar('ref_id', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    // HSS, UDM, AMF, MME, OCS, PCRF, SMF, UPF, …
    elementType: varchar('element_type', { length: 100 }).notNull(),
    // Reuse FiGHT's architecture vocab: RAN, Core, UE, OA&M.
    architectureSegment: varchar('architecture_segment', { length: 64 }),
    vendor: jsonb('vendor').$type<string[]>().notNull().default([]),         // ["Ericsson","Nokia"]
    // [{ name: "S6a", protocol: "Diameter" }, …]
    interfaces: jsonb('interfaces').$type<Record<string, unknown>[]>().notNull().default([]),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    nameIdx: index('network_elements_name_idx').on(table.name),
    refIdIdx: index('network_elements_ref_id_idx').on(table.refId),
    elementTypeIdx: index('network_elements_element_type_idx').on(table.elementType),
}));

// ============================================================================
// Signaling interfaces — SS7 / Diameter / GTP reference points
// ============================================================================

export const signalingInterfaces = pgTable('signaling_interfaces', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).unique(),
    // Natural key, e.g. "diameter:s6a".
    refId: varchar('ref_id', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    // SS7, Diameter, GTP, GTP-C, GTP-U, HTTP/2 (SBI), …
    protocol: varchar('protocol', { length: 50 }).notNull(),
    // S6a, N8, S11, Gx, … (3GPP reference point)
    referencePoint: varchar('reference_point', { length: 100 }),
    // 3GPP spec reference, e.g. "3GPP TS 29.272".
    specRef: varchar('spec_ref', { length: 255 }),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    nameIdx: index('signaling_interfaces_name_idx').on(table.name),
    refIdIdx: index('signaling_interfaces_ref_id_idx').on(table.refId),
    protocolIdx: index('signaling_interfaces_protocol_idx').on(table.protocol),
}));

// ============================================================================
// Fraud schemes — telecom fraud playbooks (SIM-swap, IRSF, Wangiri…)
// ============================================================================

export const fraudSchemes = pgTable('fraud_schemes', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).unique(),
    // Natural key, e.g. "sim-swap:port-out".
    refId: varchar('ref_id', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    // sim-swap, irsf, wangiri, smishing, pbx-hacking, …
    schemeType: varchar('scheme_type', { length: 100 }).notNull(),
    // How the money is made — free text (e.g. "premium-rate revenue share").
    monetization: text('monetization'),
    // GSMA FS.11 / FS.19 categories (B1.3). Queried via JSONB containment
    // (`gsma_fs_categories @> '["FS.11"]'`). e.g. ["FS.11", "FS.19"].
    gsmaFsCategories: jsonb('gsma_fs_categories').$type<string[]>().notNull().default([]),
    // 3GPP threat refs (B1.3) — free strings (spec / threat IDs), e.g.
    // ["TR 33.926", "TS 33.117 A.3"]. 3GPP has no FS.11-style enum.
    threeGppThreats: jsonb('three_gpp_threats').$type<string[]>().notNull().default([]),
    killChainPhases: jsonb('kill_chain_phases').$type<Record<string, unknown>[]>().notNull().default([]),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    nameIdx: index('fraud_schemes_name_idx').on(table.name),
    refIdIdx: index('fraud_schemes_ref_id_idx').on(table.refId),
    schemeTypeIdx: index('fraud_schemes_scheme_type_idx').on(table.schemeType),
}));

// Type exports
export type NetworkElement = typeof networkElements.$inferSelect;
export type NewNetworkElement = typeof networkElements.$inferInsert;
export type SignalingInterface = typeof signalingInterfaces.$inferSelect;
export type NewSignalingInterface = typeof signalingInterfaces.$inferInsert;
export type FraudScheme = typeof fraudSchemes.$inferSelect;
export type NewFraudScheme = typeof fraudSchemes.$inferInsert;
