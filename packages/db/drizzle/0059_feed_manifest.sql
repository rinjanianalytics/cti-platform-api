-- Feed manifest persistence — A2 of the declarative feed-connector engine.
--
-- Stores the parser-definition layer that `@rinjani/feed-engine` runs.
-- Scheduling, credentials, URL, format already live in `feeds_config` (the
-- existing per-source override surface used by /admin/feeds + the BullMQ
-- scheduler). This table owns only the manifest body + audit/version trail.
--
-- Versioning model: IMMUTABLE rows.
--   Each manifest save is a new row with version = max(version) + 1 for that
--   source. Rows are never UPDATE'd after insert (except is_active toggling).
--   Rollback = activate an older row. Parity-diff = compare two versions.
--   Both gates A4 needs.
--
-- Single-active invariant: a partial unique index on (source) WHERE is_active
-- forces at most one active manifest per source. The /v1/connectors/:id/activate
-- handler runs the deactivate+activate transition inside a transaction.
--
-- created_by is TEXT (not a users FK): API-key authenticated writes carry
-- subject "key:xxxxxxxx" (apps/api/src/middleware/auth.ts), which isn't a
-- valid users.id UUID. Storing the auth subject verbatim preserves the audit
-- trail without forcing a JOIN that wouldn't resolve.

CREATE TABLE IF NOT EXISTS feed_manifest (
    id                       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    source                   VARCHAR(100) NOT NULL,
    version                  INTEGER      NOT NULL,
    entity                   VARCHAR(50)  NOT NULL,
    manifest                 JSONB        NOT NULL,
    is_active                BOOLEAN      NOT NULL DEFAULT false,
    created_by               TEXT         NOT NULL,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_validated_at        TIMESTAMPTZ,
    last_validation_errors   JSONB,

    -- A (source, version) pair is unique: prevents two concurrent saves for the
    -- same source from claiming the same version number.
    CONSTRAINT feed_manifest_source_version_unique UNIQUE (source, version)
);

-- At most one active manifest per source. Partial index because most rows are
-- inactive history; the active row is the hot lookup.
CREATE UNIQUE INDEX IF NOT EXISTS feed_manifest_active_per_source
    ON feed_manifest (source)
    WHERE is_active = true;

-- Listing endpoints filter by source and active state.
CREATE INDEX IF NOT EXISTS feed_manifest_source_idx
    ON feed_manifest (source);

CREATE INDEX IF NOT EXISTS feed_manifest_entity_idx
    ON feed_manifest (entity);
