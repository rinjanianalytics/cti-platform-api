-- Track per-batch enrichment status on feed_sync_runs.
--
-- Previously `feed_sync_runs.status` covered only the ingest phase
-- (completed once IOCs landed in Postgres). With the FlowProducer pilot,
-- every feed-sync that hits AUTO_ENRICH spawns a parent job whose
-- children are the per-IOC enrichment jobs. When that parent completes
-- we stamp these columns on the same row, so the admin/feeds history
-- view can render "ingested at X, all enriched by Y."
--
-- All columns nullable / default-zero so existing rows from before this
-- migration (none in practice; `recordFeedSyncRun` was dead code) stay
-- valid. Safe to re-run.

ALTER TABLE feed_sync_runs
    ADD COLUMN IF NOT EXISTS enriched_at                  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS enrichment_children_total    INTEGER DEFAULT 0 NOT NULL,
    ADD COLUMN IF NOT EXISTS enrichment_children_done     INTEGER DEFAULT 0 NOT NULL;

CREATE INDEX IF NOT EXISTS idx_feed_sync_runs_enriched_at ON feed_sync_runs(enriched_at);
