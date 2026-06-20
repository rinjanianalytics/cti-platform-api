-- SIEM export / push audit — the signal funnel's "Actioned" provenance.
--
-- The /v1/export/* and /v1/siem/push/* routes shipped data but recorded nothing,
-- so the funnel's payoff step had no real source (the dashboard re-anchored it on
-- cases as a stopgap). One row per export/push: `channel='push'` rows are the
-- disruptive actions the funnel counts.
--
-- Idempotent: CREATE ... IF NOT EXISTS so it can be applied via db:apply or psql.

CREATE TABLE IF NOT EXISTS "siem_export_logs" (
    "id"            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 'cef' | 'leef' | 'ecs' (download) | 'splunk' | 'elastic' (push)
    "format"        varchar(20) NOT NULL,
    -- 'export' = file download; 'push' = direct ship to a SIEM
    "channel"       varchar(20) NOT NULL DEFAULT 'export',
    -- HEC URL / index for pushes; NULL for downloads
    "destination"   text,
    "record_count"  integer NOT NULL DEFAULT 0,
    -- 'success' | 'failed'
    "status"        varchar(20) NOT NULL DEFAULT 'success',
    "user_id"       text,
    "created_at"    timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT siem_export_logs_channel_check CHECK (channel IN ('export', 'push')),
    CONSTRAINT siem_export_logs_status_check  CHECK (status IN ('success', 'failed'))
);

CREATE INDEX IF NOT EXISTS "siem_export_logs_created_at_idx"
    ON "siem_export_logs" ("created_at" DESC);
CREATE INDEX IF NOT EXISTS "siem_export_logs_channel_idx"
    ON "siem_export_logs" ("channel");
