-- Work-driven enrichment for IOCs.
--
-- The CVE pattern in migration 0033 used a single "kind" NOTIFY because
-- cveEnrichmentWorker batches its own backlog. The IOC enrichment worker
-- is per-row (it calls VirusTotal / AbuseIPDB / Shodan per IOC), so we
-- can't enqueue "one job for everything". Instead, the listener handles
-- the NOTIFY by querying the un-enriched backlog and enqueueing one job
-- per IOC (rate-limited via Redis dedup so a bulk feed sync doesn't
-- stampede the external APIs).
--
-- Trigger fires when an IOC row lands with no `enriched_at` set —
-- whether on first insert or because a feed sync re-touched it without
-- enrichment metadata. The `notify_enrichment_work()` function was
-- already created in migration 0033; we just bind another trigger.

DROP TRIGGER IF EXISTS ioc_needs_enrichment ON iocs;
CREATE TRIGGER ioc_needs_enrichment
AFTER INSERT OR UPDATE OF enriched_at, enrichment_score ON iocs
FOR EACH ROW
WHEN (NEW.enriched_at IS NULL)
EXECUTE FUNCTION notify_enrichment_work('ioc-enrich');
