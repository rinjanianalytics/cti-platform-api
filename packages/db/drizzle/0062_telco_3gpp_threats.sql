-- B1.3 — GSMA / 3GPP taxonomy mapping on fraud schemes.
--
-- fraud_schemes already carries `gsma_fs_categories jsonb` (B1.1). This adds
-- the 3GPP counterpart + GIN indexes so the by-category / by-3gpp containment
-- queries (`column @> '["FS.11"]'::jsonb`) hit an index instead of scanning.
--
-- Mirrors the Sigma→MITRE meta-JSONB + JSONB-containment pattern, except the
-- telco taxonomy refs are first-class columns rather than nested in a meta blob.
--
-- 3GPP refs are stored as free strings (spec / threat IDs, e.g. "TR 33.926",
-- "TS 33.117 A.3") — 3GPP has no single FS.11-style category enum, so v1 keeps
-- it as an operator-tagged string array.

ALTER TABLE fraud_schemes
    ADD COLUMN IF NOT EXISTS three_gpp_threats JSONB NOT NULL DEFAULT '[]';

-- jsonb_path_ops GIN supports the @> containment operator the query routes use.
CREATE INDEX IF NOT EXISTS fraud_schemes_gsma_gin
    ON fraud_schemes USING GIN (gsma_fs_categories jsonb_path_ops);
CREATE INDEX IF NOT EXISTS fraud_schemes_3gpp_gin
    ON fraud_schemes USING GIN (three_gpp_threats jsonb_path_ops);
