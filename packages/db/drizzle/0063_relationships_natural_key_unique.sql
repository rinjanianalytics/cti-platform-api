-- The user-facing POST /v1/relationships (and /relationships/bulk) upserts with
--   ON CONFLICT (source_type, source_id, target_type, target_id, relationship_type)
-- but NO unique constraint on those columns ever existed — so every insert
-- through that route threw Postgres' "there is no unique or exclusion
-- constraint matching the ON CONFLICT specification". MITRE/STIX bulk paths
-- insert differently, so it stayed latent until the first telco relationship
-- (fraud_scheme -[exploits-via]-> signaling_interface) was created by hand.
--
-- Add the natural-key UNIQUE constraint the upsert requires. A relationship is
-- identified by (source_type, source_id, target_type, target_id,
-- relationship_type); exact duplicates carry no unique information, so we
-- dedup any existing ones (keep the lowest ctid) before adding the constraint.
--
-- Idempotent: dedup is a no-op when clean; constraint guarded by pg_constraint.

-- ALSO add the created_by audit column. The same two routes write it, but it
-- was never added to the table — so the INSERT failed at parse ("column
-- created_by does not exist") BEFORE ON CONFLICT was even evaluated. Both
-- breakages had to be fixed for the route to work.
ALTER TABLE relationships ADD COLUMN IF NOT EXISTS created_by varchar(128);

DO $$
BEGIN
    -- 1. Remove exact-duplicate relationships so the unique index can build.
    DELETE FROM relationships a
     USING relationships b
     WHERE a.ctid > b.ctid
       AND a.source_type = b.source_type
       AND a.source_id = b.source_id
       AND a.target_type = b.target_type
       AND a.target_id = b.target_id
       AND a.relationship_type = b.relationship_type;

    -- 2. Add the natural-key unique constraint if not already present.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'relationships_natural_key_unique'
    ) THEN
        ALTER TABLE relationships
            ADD CONSTRAINT relationships_natural_key_unique
            UNIQUE (source_type, source_id, target_type, target_id, relationship_type);
    END IF;
END$$;
