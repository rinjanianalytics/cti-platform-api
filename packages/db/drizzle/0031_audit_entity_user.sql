-- Extend audit_logs.entity_type enum to include 'user'.
--
-- The auditService.ts allow-list always included 'user', but the underlying
-- PostgreSQL enum did not — so user audit writes (role changes, deletes,
-- purges, avatar updates) were being silently dropped at insert time and
-- the catch-and-log in logAudit() swallowed the constraint violation.
--
-- Idempotent: ALTER TYPE ... ADD VALUE IF NOT EXISTS errors on duplicates
-- in some PG versions, so we use a DO block + pg_enum lookup.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum
        WHERE enumlabel = 'user'
          AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'entity_type')
    ) THEN
        ALTER TYPE entity_type ADD VALUE 'user';
    END IF;
END $$;
