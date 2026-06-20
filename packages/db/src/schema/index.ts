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

// Outbound TAXII 2.1 push targets (Phase 2 federation)
export * from './taxiiRemoteTargets';

// STIX 2.1 SDOs added in Phase 2 #1 (campaigns, courses_of_action, infrastructure)
export * from './stixEntities';

// Sandbox submissions + reports — Phase 4 #5
export * from './sandboxReports';

// External ticket links for cases — Phase 4 #6
export * from './ticketLinks';

// Report ingestion draft persistence — Phase 3 #1 follow-on
export * from './extractedReports';

// Threat-actor TTP changelog — Phase 5 #2
export * from './actorTtpChangelog';

// Hypothesis tracking + evidence — Phase 3 #5
export * from './hypotheses';

// Brand / typo-squat monitoring — Phase 5 #1
export * from './brandMonitoring';

// HIBP breach catalog (free-tier sync) — Phase 5 #3
export * from './dataBreaches';

// Dark-web monitoring via Ahmia (indexed search only) — Phase 5 #4
export * from './darkWebMonitoring';

// Paste-site monitoring (GitHub Gist firehose) — Phase 5 #5
export * from './pasteMonitoring';

// Feed connector manifests — A2 of declarative feed-connector engine
export * from './connectors';

// Telco threat-domain entities — B1.1 (network elements, signaling interfaces, fraud schemes)
export * from './telco';

// Agent memory — AA.4 (persisted agentic-analytics runs + traces)
export * from './agentRuns';

// On-chain entity model — AA.6.1 / Phase 8 (wallets; follow-the-money)
export * from './onchain';

// AI-incident model — AI vertical (incidentdatabase.ai feed)
export * from './aiIncidents';

// SIEM export/push audit — the signal funnel's "Actioned" provenance
export * from './siemExportLogs';
