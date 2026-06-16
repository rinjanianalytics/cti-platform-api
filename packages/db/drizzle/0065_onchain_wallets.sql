-- AA.6.1 / PLAN Phase 8 — on-chain entity model (follow-the-money).
--
-- Wallet entities for tracing telco-fraud cashout into crypto. Mirrors the B1
-- telco entity template: nullable stix_id + natural ref_id ("<chain>:<address>")
-- as the upsert key.
--
-- PLAN INVARIANT: on-chain attribution is CONFIDENCE-WEIGHTED, never asserted as
-- fact — entity_label/entity_type ride with confidence (0–100) + a source.
--
-- Idempotent (IF NOT EXISTS) so it applies cleanly via db:apply or psql.

CREATE TABLE IF NOT EXISTS "wallets" (
    "id"                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "stix_id"             varchar(255) UNIQUE,
    "ref_id"              varchar(255) NOT NULL UNIQUE,
    "address"             varchar(255) NOT NULL,
    "chain"               varchar(32) NOT NULL,
    "name"                varchar(500),
    "description"         text,
    "entity_label"        varchar(255),
    "entity_type"         varchar(64),
    "confidence"          integer NOT NULL DEFAULT 50,
    "attribution_source"  varchar(64),
    "risk_tags"           jsonb NOT NULL DEFAULT '[]'::jsonb,
    "external_references" jsonb NOT NULL DEFAULT '[]'::jsonb,
    "labels"              jsonb NOT NULL DEFAULT '[]'::jsonb,
    "created_at"          timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"          timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT wallets_confidence_range CHECK (confidence >= 0 AND confidence <= 100)
);

CREATE INDEX IF NOT EXISTS "wallets_ref_id_idx"       ON "wallets" ("ref_id");
CREATE INDEX IF NOT EXISTS "wallets_address_idx"      ON "wallets" ("address");
CREATE INDEX IF NOT EXISTS "wallets_chain_idx"        ON "wallets" ("chain");
CREATE INDEX IF NOT EXISTS "wallets_entity_label_idx" ON "wallets" ("entity_label");
