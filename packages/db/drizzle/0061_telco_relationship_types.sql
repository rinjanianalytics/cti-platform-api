-- B1.2 — extend the relationships.relationship_type CHECK vocab with telco
-- edge verbs. Drop + re-add (CHECK constraints aren't additive), mirroring
-- 0045_relationship_type_check.sql.
--
-- New telco verbs:
--   connects-to     network_element → network_element (over an interface)
--   uses-interface  fraud_scheme / fight_technique → signaling_interface
--   enables-fraud   network_element (misconfig) → fraud_scheme
--   exploits-via    fraud_scheme → signaling_interface
--
-- NOTE: this DB CHECK is one of THREE vocab copies kept in sync —
--   * STIX_RELATIONSHIP_TYPES (packages/core/src/stixVocab.ts) — route zod
--   * RELATIONSHIP_ENTITY_TYPES (apps/api/src/lib/schemas.ts) — source/target
--   * this CHECK
-- All three must list the telco additions or telco relationships are rejected
-- at one layer or another.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'relationships_relationship_type_check'
    ) THEN
        ALTER TABLE relationships DROP CONSTRAINT relationships_relationship_type_check;
    END IF;

    ALTER TABLE relationships
        ADD CONSTRAINT relationships_relationship_type_check
        CHECK (relationship_type IN (
            -- STIX 2.1 §5.7 SRO vocab (unchanged from 0045)
            'uses', 'targets', 'attributed-to', 'mitigates', 'derived-from',
            'indicates', 'related-to', 'beacons-to', 'communicates-with',
            'exfiltrates-to', 'downloads', 'drops', 'exploits',
            'originates-from', 'characterizes', 'av-classification',
            'controls', 'delivers', 'hosts', 'owns', 'authored-by',
            'sub-technique-of', 'revoked-by', 'detects', 'impersonates',
            'unknown',
            -- B1.2 telco edge verbs
            'connects-to', 'uses-interface', 'enables-fraud', 'exploits-via'
        ));
END$$;
