-- Alerts — durable triage queue (replaces the in-memory alertStore).
--
-- Alerts previously lived in a process-local array that reset on every API
-- restart and only filtered by severity/unread. This makes them durable and
-- server-side-filterable (severity / source / type / read). The row shape is a
-- superset of the old in-memory object, so existing clients are unaffected.
--
-- `id` is text — the alerts worker uses the BullMQ job id as the alert id, which
-- isn't always a UUID.
--
-- Idempotent: CREATE ... IF NOT EXISTS so it can be applied via db:apply or psql.

CREATE TABLE IF NOT EXISTS "alerts" (
    "id"              text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    "severity"        varchar(20) NOT NULL,
    "type"            varchar(60) NOT NULL,
    "title"           text NOT NULL,
    "message"         text NOT NULL,
    "source"          text,
    "metadata"        jsonb NOT NULL DEFAULT '{}'::jsonb,
    "read"            boolean NOT NULL DEFAULT false,
    "acknowledged"    boolean NOT NULL DEFAULT false,
    "acknowledged_at" timestamptz,
    "created_at"      timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"      timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "alerts_created_at_idx" ON "alerts" ("created_at" DESC);
CREATE INDEX IF NOT EXISTS "alerts_severity_idx"   ON "alerts" ("severity");
CREATE INDEX IF NOT EXISTS "alerts_read_idx"       ON "alerts" ("read");
CREATE INDEX IF NOT EXISTS "alerts_source_idx"     ON "alerts" ("source");
CREATE INDEX IF NOT EXISTS "alerts_type_idx"       ON "alerts" ("type");
