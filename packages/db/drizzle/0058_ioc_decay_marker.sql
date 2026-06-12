-- IOC decay marker — `decayed_at` column + un-decay trigger on resighting.
--
-- The existing confidenceDecay BullMQ job (apps/api/src/queues/workers/
-- retentionWorker.ts -> processConfidenceDecay) already runs daily and
-- multiplies risk_score by an exponential decay factor per IOC type. What
-- it doesn't do is mark IOCs that have crossed their per-type staleness
-- threshold (IPs: 30d, domains: 60d, hashes: 180d, etc. — see
-- DECAY_RATES in apps/api/src/services/confidenceDecay.ts).
--
-- This migration adds the marker column so the decay job (updated in the
-- same PR) can stamp NOW() onto stale IOCs, and downstream list / stats
-- endpoints can filter them out with `WHERE decayed_at IS NULL`.
--
-- The partial index covers only active (non-decayed) IOCs, which is the
-- universe every dashboard query cares about. Decayed IOCs are kept (for
-- forensic / historical investigations) but excluded from default lists.
--
-- The trigger handles re-sightings transparently: any UPDATE that bumps
-- last_seen (i.e. a feed-sync upsert finding the same IOC again) clears
-- decayed_at back to NULL. This means every current and future call site
-- that re-ingests an IOC un-decays it without needing to know about
-- decayed_at at all. Zero extra coordination across the codebase.

ALTER TABLE iocs ADD COLUMN IF NOT EXISTS decayed_at timestamptz;

CREATE INDEX IF NOT EXISTS iocs_decayed_at_partial_idx
    ON iocs(decayed_at) WHERE decayed_at IS NULL;

CREATE OR REPLACE FUNCTION iocs_undecay_on_resight()
RETURNS trigger AS $$
BEGIN
    -- Resight = last_seen advanced. Only act when the IOC is currently
    -- marked decayed; otherwise this is a no-op so the trigger doesn't
    -- pollute UPDATE plans for unrelated columns.
    IF NEW.last_seen IS DISTINCT FROM OLD.last_seen
       AND OLD.decayed_at IS NOT NULL
    THEN
        NEW.decayed_at := NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS iocs_undecay_trigger ON iocs;
CREATE TRIGGER iocs_undecay_trigger
    BEFORE UPDATE ON iocs
    FOR EACH ROW
    EXECUTE FUNCTION iocs_undecay_on_resight();
