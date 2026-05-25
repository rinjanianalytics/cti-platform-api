/**
 * Database Schema - Index
 * 
 * Exports all schema tables and relations.
 */

// User & Auth tables
export * from './users';

// Threat Intelligence tables
export * from './threats';

// Intel Feed tables (IOCs, CVEs, Pulses)
export * from './feeds';

// MITRE ATT&CK tables
export * from './mitre';

// Opengate Subscriptions
export * from './subscriptions';

// Webhooks
export * from './webhooks';

// Audit & Data Versioning
export * from './audit';

// AI Analysis Cache
export * from './aiCache';

// Sightings (IOC observation tracking)
export * from './sightings';

// Warninglists (false-positive mitigation)
export * from './warninglists';

// Playbooks (event-driven automation)
export * from './playbooks';

// Roles & Permissions (RBAC definitions)
export * from './roles';

// Configuration (feeds, API keys, services)
export * from './config';

// In-app Notifications
export * from './notifications';

// MITRE FiGHT (5G Hierarchy of Threats)
export * from './fight';

// MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
export * from './atlas';

// Admin-editable overrides for scheduled BullMQ jobs
// NOTE: oauthIdentities lives inside ./users (alongside its parent table).
export * from './scheduledJobOverrides';

// Per-run feed-sync audit trail (recordFeedSyncRun / getFeedSyncHistory)
export * from './feedSyncRuns';
