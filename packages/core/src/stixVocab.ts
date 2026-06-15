/**
 * STIX 2.1 controlled vocabularies + the small set of project-specific
 * extensions the codebase emits.
 *
 * Used by:
 *   - DB CHECK constraint in `0045_relationship_type_check.sql` (kept in
 *     lockstep manually — if you add a value here, add it there)
 *   - Zod enum on `POST /v1/relationships`
 *   - The auto-Neo4j-hydrate side-effect that fires on every
 *     relationships INSERT
 */

/**
 * Relationship type vocabulary. Combines STIX 2.1 §5.7 SRO common values
 * with project-specific extensions:
 *   - `indicates` / `exploits` are written by the synthetic-relationship
 *     builder in `apps/api/src/routes/v1/stixPipeline.ts`.
 *   - `unknown` is written by the MITRE worker as a fallback when a STIX
 *     bundle row omits `relationship_type` (rare but defensive).
 */
export const STIX_RELATIONSHIP_TYPES = [
    'uses',
    'targets',
    'attributed-to',
    'mitigates',
    'derived-from',
    'indicates',
    'related-to',
    'beacons-to',
    'communicates-with',
    'exfiltrates-to',
    'downloads',
    'drops',
    'exploits',
    'originates-from',
    'characterizes',
    'av-classification',
    'controls',
    'delivers',
    'hosts',
    'owns',
    'authored-by',
    'sub-technique-of',
    'revoked-by',
    'detects',
    'impersonates',
    'unknown',
    // Telco vertical (B1.2) — kept in sync with the DB CHECK in
    // 0061_telco_relationship_types.sql and RELATIONSHIP_ENTITY_TYPES.
    'connects-to',
    'uses-interface',
    'enables-fraud',
    'exploits-via',
] as const;

export type STIXRelationshipType = typeof STIX_RELATIONSHIP_TYPES[number];

/** True if `t` is one of the known relationship types. */
export function isKnownRelationshipType(t: string): t is STIXRelationshipType {
    return (STIX_RELATIONSHIP_TYPES as readonly string[]).includes(t);
}
