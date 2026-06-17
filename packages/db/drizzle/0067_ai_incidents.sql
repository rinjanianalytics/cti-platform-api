-- AI Incident Database feed (PLAN AI-vertical) — real-world AI harm/failure
-- incidents from incidentdatabase.ai, the live "AI threat landscape" signal.
--
-- A DEDICATED table, deliberately NOT atlas_case_studies: MITRE ATLAS case
-- studies are ~30 curated incidents mapped to AML techniques; AID is ~1500
-- raw incidents with no technique mapping. Mixing them would distort the
-- ATLAS coverage view. AI incidents are their own domain entity, mirroring
-- telco (network_elements/fraud_schemes) and on-chain (wallets).
--
-- Natural key: incident_id (AID's stable integer id) — upsert target.
-- Idempotent (IF NOT EXISTS) so it applies cleanly via db:apply or psql.

CREATE TABLE IF NOT EXISTS "ai_incidents" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "incident_id"    integer NOT NULL UNIQUE,          -- AID incident_id (stable)
    "title"          text NOT NULL,
    "description"    text,
    "incident_date"  date,                             -- YYYY-MM-DD from AID
    "deployers"      jsonb NOT NULL DEFAULT '[]'::jsonb, -- alleged deployer slugs
    "developers"     jsonb NOT NULL DEFAULT '[]'::jsonb, -- alleged developer slugs
    "harmed_parties" jsonb NOT NULL DEFAULT '[]'::jsonb, -- alleged harmed parties
    "report_ids"     jsonb NOT NULL DEFAULT '[]'::jsonb, -- linked AID report numbers
    "report_count"   integer NOT NULL DEFAULT 0,        -- # of linked reports (corroboration)
    "tags"           jsonb NOT NULL DEFAULT '[]'::jsonb, -- derived: ai-incident + entity slugs
    "url"            varchar(512),                      -- https://incidentdatabase.ai/cite/<id>
    "source"         varchar(32) NOT NULL DEFAULT 'aiid',
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"     timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "ai_incidents_incident_id_idx"   ON "ai_incidents" ("incident_id");
CREATE INDEX IF NOT EXISTS "ai_incidents_incident_date_idx" ON "ai_incidents" ("incident_date");
CREATE INDEX IF NOT EXISTS "ai_incidents_source_idx"        ON "ai_incidents" ("source");
