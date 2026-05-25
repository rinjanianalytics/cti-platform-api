-- Promote the feed_sync_runs table from a runtime `CREATE TABLE IF NOT
-- EXISTS` block in apps/api/src/services/configStore.ts into a real
-- migration. The runtime helper emitted Postgres NOTICEs on every boot
-- ("relation already exists, skipping") and bypassed Drizzle's schema
-- ownership, making the column set invisible to the schema package.
--
-- `IF NOT EXISTS` is preserved on every statement so the migration is a
-- no-op on databases that already have the table (every environment
-- where the API has booted at least once). Column types and defaults
-- mirror the previous runtime DDL exactly — no data shape change.

CREATE TABLE IF NOT EXISTS feed_sync_runs (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    feed_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    duration_ms     INTEGER,
    items_ingested  INTEGER DEFAULT 0,
    errors          INTEGER DEFAULT 0,
    error_details   TEXT,
    triggered_by    TEXT NOT NULL DEFAULT 'scheduler'
);

CREATE INDEX IF NOT EXISTS idx_feed_sync_runs_feed_id    ON feed_sync_runs(feed_id);
CREATE INDEX IF NOT EXISTS idx_feed_sync_runs_started_at ON feed_sync_runs(started_at DESC);
