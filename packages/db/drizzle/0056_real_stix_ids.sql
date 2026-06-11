-- Add real STIX IDs to the MITRE catalog tables so the actor TTP changelog
-- (and any other code paths that reference relationships.source_id /
-- relationships.target_id) can JOIN against threat_actors and techniques to
-- resolve human-readable names.
--
-- Background: when the MITRE sync ingests intrusion-sets, attack-patterns,
-- and malware it stores a SYNTHETIC stix_id of the form `mitre--<mitreId>`
-- (see apps/worker/src/feeds/mitre.ts ~lines 225, 264). The `relationships`
-- table, however, stores the REAL STIX IDs from the upstream bundle
-- (`intrusion-set--<uuid>`, `attack-pattern--<uuid>`). The two never agree,
-- so a LEFT JOIN on `stix_id` fails and the changelog UI ends up showing
-- raw STIX UUIDs instead of "APT28" / "Spearphishing Attachment".
--
-- Techniques don't even have a stix_id column — the synthetic prefix
-- convention was never extended to that table. Adding `real_stix_id`
-- everywhere (nullable, indexed) gives a clean join key without breaking
-- any code that already depends on the synthetic `stix_id`.
--
-- Population happens via the updated MITRE sync code (this PR) writing
-- obj.id directly. Run mitreSync ad-hoc after deploy to backfill in one
-- pass; subsequent scheduled runs upsert and keep it fresh.

ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS real_stix_id varchar(255);
ALTER TABLE techniques    ADD COLUMN IF NOT EXISTS real_stix_id varchar(255);
ALTER TABLE malware       ADD COLUMN IF NOT EXISTS real_stix_id varchar(255);

CREATE INDEX IF NOT EXISTS threat_actors_real_stix_id_idx ON threat_actors(real_stix_id);
CREATE INDEX IF NOT EXISTS techniques_real_stix_id_idx    ON techniques(real_stix_id);
CREATE INDEX IF NOT EXISTS malware_real_stix_id_idx       ON malware(real_stix_id);
