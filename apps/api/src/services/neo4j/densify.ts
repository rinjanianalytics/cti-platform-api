/**
 * Neo4j Cross-Domain Densification — Barrel
 *
 * Sub-modules:
 *   - densify/crossDomainSync.ts → IOC↔Wallet (REFERS_TO) + IOC→Actor (ATTRIBUTED_TO)
 */

export { densifyCrossDomain } from './densify/crossDomainSync';
export type { DensifyResult } from './densify/crossDomainSync';
