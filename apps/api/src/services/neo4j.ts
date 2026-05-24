/**
 * Neo4j Graph Database Service — Barrel Re-export
 *
 * Singleton Neo4j driver + PostgreSQL → Neo4j sync operations.
 * All sync jobs run via BullMQ (see queues/index.ts).
 *
 * Graph Model:
 *   Nodes:  Actor, Technique, Tactic, Malware, Tool, IOC, CVE, Pulse, WebSource, Campaign
 *   Edges:  USES, BELONGS_TO, PARENT_OF, FOUND_IN, ATTRIBUTED_TO, REFERENCES,
 *           SIMILAR_TO, MENTIONED_IN, DISCOVERED_BY, PART_OF_CAMPAIGN
 */

// Driver & infrastructure
export { getNeo4jDriver, closeNeo4j, checkNeo4jHealth, ensureNeo4jConstraints, getNeo4jStats } from './neo4j/driver';

// MITRE entity sync
export { syncActors, syncTactics, syncTechniques, syncMalware, syncTools } from './neo4j/syncEntities';

// MITRE relationship sync
export { syncRelationships } from './neo4j/syncRelationships';

// IOC sync (pulses, CVEs, all IOCs, similarity)
export { syncPulsesAndIOCs, syncCVEs, syncAllIOCs, syncSimilarIOCs } from './neo4j/syncIOCs';

// Full sync orchestrator
export { syncAllToNeo4j } from './neo4j/syncAll';
export type { Neo4jSyncResult } from './neo4j/syncAll';
