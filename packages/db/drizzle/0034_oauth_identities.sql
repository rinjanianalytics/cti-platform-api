-- Move oauth_identities from a runtime `ensureXTable()` helper in
-- apps/api/src/services/oauth.ts into a proper migration. The runtime
-- helper kept the schema invisible to Drizzle introspection and meant
-- the OAuth login flow ran a CREATE TABLE IF NOT EXISTS on every sign-in.
--
-- Idempotent: keeps the existing table (and data) if it was already
-- created by the runtime helper.

CREATE TABLE IF NOT EXISTS oauth_identities (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider      VARCHAR(32) NOT NULL,
    subject       VARCHAR(128) NOT NULL,
    email_at_link VARCHAR(255),
    linked_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    CONSTRAINT oauth_identities_provider_subject_unique UNIQUE (provider, subject)
);
