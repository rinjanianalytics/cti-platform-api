-- Create the `detection_rules` table that the MISP Galaxy sigma-cluster
-- sync writes to. The table is fully defined in
-- packages/db/src/schema/threats.ts but no migration ever created it, so
-- production hits `42P01: relation "detection_rules" does not exist` on
-- the very first SELECT in the sigma processor — the try/catch around
-- the cluster swallows the error, `stats.total` increments once, and the
-- rest of the 3,132 sigma-rules.json entries get skipped silently.
-- (Logged for months as `Failed to sync sigma cluster sigma-rules.json`
-- with a truncated error message that hid the actual postgres code.)
--
-- Same drift-recovery pattern as 0043_schema_drift_recovery.sql, which
-- caught the equivalent issue for `galaxy_clusters` on 2026-05-28.
-- IF NOT EXISTS guards so this migration is safe to re-run on a database
-- where the table was hand-created by some earlier emergency fix.

CREATE TABLE IF NOT EXISTS "detection_rules" (
    "id"                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "rule_type"           varchar(50)  NOT NULL DEFAULT 'sigma',
    "uuid"                varchar(255) NOT NULL UNIQUE,
    "name"                varchar(1000) NOT NULL,
    "description"         text,
    "severity"            varchar(20),
    "status"              varchar(20),
    "tags"                jsonb DEFAULT '[]'::jsonb,
    "detection"           jsonb DEFAULT '{}'::jsonb,
    "meta"                jsonb DEFAULT '{}'::jsonb,
    "external_references" jsonb DEFAULT '[]'::jsonb,
    "source"              varchar(100) DEFAULT 'misp-galaxy',
    "synced_at"           timestamptz,
    "created_at"          timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"          timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "detection_rules_type_idx"     ON "detection_rules" ("rule_type");
CREATE INDEX IF NOT EXISTS "detection_rules_uuid_idx"     ON "detection_rules" ("uuid");
CREATE INDEX IF NOT EXISTS "detection_rules_name_idx"     ON "detection_rules" ("name");
CREATE INDEX IF NOT EXISTS "detection_rules_severity_idx" ON "detection_rules" ("severity");
