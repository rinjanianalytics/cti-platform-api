-- Admin-editable overrides for code-defined scheduled jobs.
--
-- The 17 BullMQ repeatable jobs in apps/api/src/queues/scheduler.ts ship
-- with hardcoded cron expressions. This table lets admins toggle them off
-- or pick a curated interval preset (every 15m / hourly / 4h / daily /
-- weekly) without a redeploy. A missing row = use the code default.
--
-- `job_key` matches the SCHEDULES key (e.g. 'otxSync', 'cisaSync').
-- `interval_preset` is null when the admin hasn't changed the cadence.

CREATE TABLE IF NOT EXISTS scheduled_job_overrides (
    job_key          TEXT PRIMARY KEY,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    interval_preset  TEXT,                       -- '15m' | '30m' | '1h' | '4h' | '6h' | 'daily' | 'weekly' | NULL
    payload          JSONB,                      -- optional override of the job's payload
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by       UUID                        -- soft FK to users(id); kept loose so a deleted admin doesn't break the row
);
