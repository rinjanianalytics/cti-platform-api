-- Work-driven enrichment via Postgres NOTIFY.
--
-- Instead of waking the CVE enrichment worker on a daily cron, fire a
-- NOTIFY whenever a vulnerability row lands without a CVSS score. The
-- worker subscribes to the channel and (with Redis-side dedup) drains
-- whatever backlog exists. This collapses "latency from data-arrival to
-- enrichment" from ~24h to seconds, without piling jobs in the queue.
--
-- The notification payload is just the kind string — the worker queries
-- the DB for the actual backlog, so we don't need entity IDs in transit.
-- This naturally absorbs bulk inserts: 100 rows = 100 NOTIFYs all asking
-- for the same kind of work; Redis dedup collapses them to one enqueue.

CREATE OR REPLACE FUNCTION notify_enrichment_work() RETURNS TRIGGER AS $$
BEGIN
    -- TG_ARGV[0] is the work kind, set on each CREATE TRIGGER call below.
    PERFORM pg_notify('rinjani_work', TG_ARGV[0]);
    RETURN NULL;  -- AFTER trigger; return value ignored
END;
$$ LANGUAGE plpgsql;

-- CVE enrichment — fires whenever a vulnerability row's effective
-- cvss_score is null (newly inserted or updated to null).
DROP TRIGGER IF EXISTS vuln_needs_cvss_enrichment ON vulnerabilities;
CREATE TRIGGER vuln_needs_cvss_enrichment
AFTER INSERT OR UPDATE OF cvss_score ON vulnerabilities
FOR EACH ROW
WHEN (NEW.cvss_score IS NULL)
EXECUTE FUNCTION notify_enrichment_work('cve-enrich');
