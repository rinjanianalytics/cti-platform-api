-- Intel reports — broad threat-intel narrative ingestion (RSS).
-- Phase 1 of RSS + extraction. Generalises telco_advisories; the extraction
-- columns (entities / extraction_status / llm_provider) are filled in Phase 2/3.
-- Idempotent (safe to re-run); applied by db:apply (__sql_migrations tracking).

CREATE TABLE IF NOT EXISTS intel_reports (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source             varchar(64)   NOT NULL,
    external_id        varchar(1024) NOT NULL,
    title              text          NOT NULL,
    url                text          NOT NULL,
    summary            text,
    published_at       timestamptz,
    tags               jsonb         NOT NULL DEFAULT '[]'::jsonb,
    entities           jsonb         NOT NULL DEFAULT '{}'::jsonb,
    extraction_status  varchar(20)   NOT NULL DEFAULT 'pending',
    llm_provider       varchar(50),
    created_at         timestamptz   NOT NULL DEFAULT now(),
    updated_at         timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT intel_reports_external_id_unique UNIQUE (external_id)
);

CREATE INDEX IF NOT EXISTS intel_reports_published_idx ON intel_reports (published_at);
CREATE INDEX IF NOT EXISTS intel_reports_status_idx    ON intel_reports (extraction_status);
CREATE INDEX IF NOT EXISTS intel_reports_source_idx    ON intel_reports (source);
