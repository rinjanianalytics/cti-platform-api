-- AA.6.2 / Phase 8 — extend the relationships.relationship_type CHECK vocab with
-- on-chain "follow-the-money" edge verbs. Drop + re-add (CHECK constraints
-- aren't additive), mirroring 0061_telco_relationship_types.sql.
--
-- New verbs:
--   sent-funds-to    wallet → wallet (fund flow)
--   controls-wallet  actor → wallet (attribution)
--   cashed-out-to    fraud_scheme → wallet (telco fraud → crypto cashout bridge)
--
-- THREE vocab copies kept in sync (see 0061):
--   * STIX_RELATIONSHIP_TYPES (packages/core/src/stixVocab.ts)
--   * RELATIONSHIP_ENTITY_TYPES (apps/api/src/lib/schemas.ts) — adds 'wallet'
--   * this CHECK

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
            -- STIX 2.1 §5.7 SRO vocab
            'uses', 'targets', 'attributed-to', 'mitigates', 'derived-from',
            'indicates', 'related-to', 'beacons-to', 'communicates-with',
            'exfiltrates-to', 'downloads', 'drops', 'exploits',
            'originates-from', 'characterizes', 'av-classification',
            'controls', 'delivers', 'hosts', 'owns', 'authored-by',
            'sub-technique-of', 'revoked-by', 'detects', 'impersonates',
            'unknown',
            -- B1.2 telco edge verbs
            'connects-to', 'uses-interface', 'enables-fraud', 'exploits-via',
            -- AA.6.2 on-chain follow-the-money edge verbs
            'sent-funds-to', 'controls-wallet', 'cashed-out-to'
        ));
END$$;
