-- Tier-2 telco intel: telecom-keyword-filtered security news/advisories from
-- free RSS sources. Reporting layer, distinct from CVEs/pulses. Idempotent.
CREATE TABLE IF NOT EXISTS telco_advisories (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source        varchar(64) NOT NULL,
    external_id   varchar(1024) NOT NULL UNIQUE,
    title         text NOT NULL,
    url           text NOT NULL,
    summary       text,
    tags          jsonb NOT NULL DEFAULT '[]'::jsonb,
    published_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS telco_advisories_published_idx ON telco_advisories (published_at);
