-- Telco threat-domain entities — B1.1 of the Telco vertical.
--
-- Three ENTITY tables. The 5G THREAT model already lives in the fight_*
-- tables (MITRE FiGHT — tactics/techniques/mitigations incl. TA5001 Fraud);
-- B1 does NOT rebuild it. These add the network-element / signaling /
-- fraud-scheme entity layer FiGHT lacks. B1.2 bridges them to FiGHT via the
-- `relationships` table + the Neo4j auto-hydrate hook.
--
-- Column shape mirrors the Phase-2 STIX SDO tables (migration 0046), with
-- two deliberate differences:
--   * stix_id is NULLABLE — telco entities aren't STIX objects, so we don't
--     mint synthetic STIX ids. Unique when present (Postgres permits multiple
--     NULLs under a UNIQUE constraint).
--   * ref_id is the natural key — NOT NULL + UNIQUE, used for idempotent
--     operator upserts.
--
-- No existing table is altered.

CREATE TABLE IF NOT EXISTS network_elements (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id              VARCHAR(255) UNIQUE,
    ref_id               VARCHAR(255) NOT NULL UNIQUE,
    name                 VARCHAR(500) NOT NULL,
    description          TEXT,
    element_type         VARCHAR(100) NOT NULL,
    architecture_segment VARCHAR(64),
    vendor               JSONB        NOT NULL DEFAULT '[]',
    interfaces           JSONB        NOT NULL DEFAULT '[]',
    external_references  JSONB        NOT NULL DEFAULT '[]',
    labels               JSONB        NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS network_elements_name_idx         ON network_elements (name);
CREATE INDEX IF NOT EXISTS network_elements_ref_id_idx       ON network_elements (ref_id);
CREATE INDEX IF NOT EXISTS network_elements_element_type_idx ON network_elements (element_type);

CREATE TABLE IF NOT EXISTS signaling_interfaces (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id              VARCHAR(255) UNIQUE,
    ref_id               VARCHAR(255) NOT NULL UNIQUE,
    name                 VARCHAR(500) NOT NULL,
    description          TEXT,
    protocol             VARCHAR(50)  NOT NULL,
    reference_point      VARCHAR(100),
    spec_ref             VARCHAR(255),
    external_references  JSONB        NOT NULL DEFAULT '[]',
    labels               JSONB        NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS signaling_interfaces_name_idx     ON signaling_interfaces (name);
CREATE INDEX IF NOT EXISTS signaling_interfaces_ref_id_idx   ON signaling_interfaces (ref_id);
CREATE INDEX IF NOT EXISTS signaling_interfaces_protocol_idx ON signaling_interfaces (protocol);

CREATE TABLE IF NOT EXISTS fraud_schemes (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    stix_id              VARCHAR(255) UNIQUE,
    ref_id               VARCHAR(255) NOT NULL UNIQUE,
    name                 VARCHAR(500) NOT NULL,
    description          TEXT,
    scheme_type          VARCHAR(100) NOT NULL,
    monetization         TEXT,
    gsma_fs_categories   JSONB        NOT NULL DEFAULT '[]',
    kill_chain_phases    JSONB        NOT NULL DEFAULT '[]',
    external_references  JSONB        NOT NULL DEFAULT '[]',
    labels               JSONB        NOT NULL DEFAULT '[]',
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS fraud_schemes_name_idx        ON fraud_schemes (name);
CREATE INDEX IF NOT EXISTS fraud_schemes_ref_id_idx      ON fraud_schemes (ref_id);
CREATE INDEX IF NOT EXISTS fraud_schemes_scheme_type_idx ON fraud_schemes (scheme_type);
