/**
 * API v1 Router
 *
 * Thin routing layer that mounts domain-specific sub-modules.
 * All handler logic lives in ./v1/ sub-modules.
 */

import { Hono } from 'hono';

// Domain sub-modules (extracted from this file)
import vulnRoutes from './v1/vulnerabilities';
import iocRoutes from './v1/iocs';
import threatRoutes from './v1/threats';
import statsRoutes from './v1/stats';
import mitreRoutes from './v1/mitre';
import graphRoutes from './v1/graph';
import v1SearchRoutes from './v1/search';
import intelligenceRoutes from './v1/intelligence';
import sightingRoutes from './v1/sightings';
import correlationRoutes from './v1/correlation';
import fightRoutes from './v1/fight';
import atlasRoutes from './v1/atlas';

// Existing sub-routers (unchanged)
import searchRoutes from './search';
import exportRoutes from './export';
import enrichRoutes from './enrich';
import monitoringRoutes from './monitoring';
import webhookRoutes from './webhooks';
import auditRoutes from './audit';
import warninglistRoutes from './v1/warninglists';
import playbookRoutes from './v1/playbooks';
import configRoutes from './v1/config';
import batchRoutes from './v1/batch';
import stixPipeline from './v1/stixPipeline';
import yaraRoutes from './v1/yara';
import sigmaRoutes from './v1/sigma';
import taxiiPushRoutes from './v1/taxiiPush';
import taxonomyRoutes from './v1/taxonomies';
import exportEnhancedRoutes from './v1/exportEnhanced';
import exportSiemRoutes from './v1/exportSiem';
import sandboxRoutes from './v1/sandbox';
import ticketingRoutes from './v1/ticketing';
import ticketingWebhookRoutes from './v1/ticketingWebhooks';
import blocklistFeedRoutes from './v1/blocklistFeed';
import caseRoutes from './v1/cases';
import reputationRoutes from './v1/reputation';
import analyzerRoutes from './v1/analyzers';
import watchlistRoutes from './v1/watchlists';
import scheduledReportRoutes from './v1/scheduled-reports';
import relationshipRoutes from './v1/relationships';
import landscapeRoutes from './v1/landscape';
import commentRoutes from './v1/comments';
import retentionRoutes from './v1/retention';
import enrichmentProviderRoutes from './v1/enrichment-providers';
import mcpRoutes from './v1/mcp';
import eventsRoutes from './v1/events';
import watchRoutes from './v1/watch';
import timelineRoutes from './v1/timeline';
import reportRoutes from './v1/reports';
import hypothesesRoutes from './v1/hypotheses';
import brandMonitorRoutes from './v1/brandMonitor';
import actorTtpChangelogRoutes from './v1/actorTtpChangelog';
import dataBreachRoutes from './v1/dataBreaches';
import darkWebRoutes from './v1/darkWebMonitoring';
import pasteMonitorRoutes from './v1/pasteMonitoring';
import connectorRoutes from './v1/connectors';

const v1 = new Hono();

// ── Audit middleware: auto-log all entity mutations (POST/PUT/PATCH/DELETE) ──
import { auditMiddleware } from '../middleware/auditMiddleware';
v1.use('*', auditMiddleware());

// API info
v1.get('/', (c) => {
    return c.json({
        version: 'v1',
        status: 'stable',
        endpoints: {
            threats: '/v1/threats',
            indicators: '/v1/indicators',
            vulnerabilities: '/v1/vulnerabilities',
            iocs: '/v1/iocs',
            pulses: '/v1/pulses',
            stats: '/v1/stats',
            monitoring: '/v1/monitoring',
            search: '/v1/search',
            export: '/v1/export',
            enrich: '/v1/enrich',
            webhooks: '/v1/webhooks',
            audit: '/v1/audit',
            sightings: '/v1/sightings',
            warninglists: '/v1/warninglists',
            correlation: '/v1/correlation',
            playbooks: '/v1/playbooks',
            yara: '/v1/yara',
            sigma: '/v1/sigma',
            stix: '/v1/stix',
            instantSearch: '/v1/search/instant',
            fight: '/v1/fight',
            atlas: '/v1/atlas',
            taxonomies: '/v1/taxonomies',
            exportMISP: '/v1/export/misp',
            exportRules: '/v1/export/rules',
            exportReport: '/v1/export/report',
            cases: '/v1/cases',
            reputation: '/v1/reputation',
            analyzers: '/v1/analyzers',
            watchlists: '/v1/watchlists',
            reports: '/v1/reports',
            relationships: '/v1/relationships',
            landscape: '/v1/landscape',
            comments: '/v1/comments',
            retention: '/v1/retention',
            enrichmentProviders: '/v1/enrichment-providers',
        },
    });
});

// ============================================================================
// Domain Sub-Modules
// ============================================================================

v1.route('/', vulnRoutes);       // /vulnerabilities, /vulnerabilities/:cveId
v1.route('/', iocRoutes);        // /iocs, /iocs/:idOrValue
v1.route('/', threatRoutes);     // /pulses, /threats, /threats/:id, /indicators
v1.route('/', statsRoutes);      // /stats/*, /tactics, /monitoring/*
v1.route('/', mitreRoutes);      // /techniques, /threat-actors, /malware, /tools
v1.route('/', graphRoutes);      // /graph/layout, /graph/neo4j/*
v1.route('/', v1SearchRoutes);   // /search, /search/vector, /search/similar/*
v1.route('/', intelligenceRoutes); // /intelligence/ioc/:value, /intelligence/cve/:cveId
v1.route('/', sightingRoutes);   // /iocs/:id/sightings, /sightings/recent, /sightings/stats
v1.route('/', correlationRoutes); // /iocs/:id/correlate, /iocs/:id/correlations, /correlation/batch
v1.route('/fight', fightRoutes);  // /fight/matrix, /fight/techniques, /fight/tactics, /fight/stats
v1.route('/atlas', atlasRoutes);  // /atlas/matrix, /atlas/techniques, /atlas/tactics, /atlas/stats

// ============================================================================
// Existing Sub-Routers
// ============================================================================

v1.route('/search', searchRoutes);       // Deep search functionality
v1.route('/export', exportRoutes);       // CSV/JSON/STIX export
v1.route('/enrich', enrichRoutes);       // IOC enrichment
v1.route('/monitoring', monitoringRoutes); // Advanced monitoring
v1.route('/webhooks', webhookRoutes);    // Webhook subscriptions
v1.route('/audit', auditRoutes);         // Audit logs
v1.route('/warninglists', warninglistRoutes); // False-positive mitigation
v1.route('/playbooks', playbookRoutes);      // Event-driven automation
v1.route('/', configRoutes);                 // Config management (feeds, API keys, services)
v1.route('/', batchRoutes);                  // Batch operations (bulk update/delete/tag)
v1.route('/', stixPipeline);                 // STIX 2.1 import/export/validate
v1.route('/', yaraRoutes);                   // YARA rule matching engine
v1.route('/', sigmaRoutes);                  // Sigma rule library (/sigma/*)
v1.route('/', taxiiPushRoutes);              // Outbound TAXII push (/taxii/remote-targets/*)
v1.route('/', taxonomyRoutes);               // Taxonomy & tag namespace system
v1.route('/', exportEnhancedRoutes);         // Enhanced export (MISP, Suricata, reports)
v1.route('/', exportSiemRoutes);             // SIEM export (CEF, LEEF, ECS NDJSON)
v1.route('/', sandboxRoutes);                // Sandbox submissions + reports (Phase 4 #5)
v1.route('/', ticketingRoutes);              // External ticket links for cases (Phase 4 #6)
v1.route('/', ticketingWebhookRoutes);       // Inbound GitHub webhook → auto-flip linked status (Phase 4 #6b)
v1.route('/', blocklistFeedRoutes);          // Vendor firewall feeds (Fortinet, PAN, Cisco)
v1.route('/', caseRoutes);                   // Case / investigation management
v1.route('/', reputationRoutes);             // IP/domain reputation & blocklists
v1.route('/', analyzerRoutes);               // Multi-analyzer pipeline
v1.route('/', watchlistRoutes);              // IOC watchlists
v1.route('/', scheduledReportRoutes);        // Scheduled intelligence reports
v1.route('/', relationshipRoutes);           // Entity relationship management
v1.route('/', landscapeRoutes);              // Threat landscape metrics
v1.route('/', commentRoutes);                // Entity comments & annotations
v1.route('/', retentionRoutes);              // Data retention policies
v1.route('/', enrichmentProviderRoutes);     // Enrichment provider management
v1.route('/', mcpRoutes);                    // MCP tools registry
v1.route('/', eventsRoutes);                 // /events — semantic "what changed" stream
v1.route('/', watchRoutes);                  // /watch — personal pinned entities (IOC/CVE/actor)
v1.route('/', timelineRoutes);               // /timeline/:type/:id — per-entity activity sparkline
v1.route('/', reportRoutes);                 // /reports/* — Phase 3 #1 report ingestion + review/commit
v1.route('/', hypothesesRoutes);             // /hypotheses/* — Phase 3 #5 hypothesis tracking + LLM grading
v1.route('/', brandMonitorRoutes);           // /brand/* — Phase 5 #1 brand / typo-squat monitoring
v1.route('/', actorTtpChangelogRoutes);      // /ttp-changes + /actors/:id/ttp-changes — Phase 5 #2
v1.route('/', dataBreachRoutes);             // /data-breaches/* — Phase 5 #3 HIBP breach catalog (free-tier sync)
v1.route('/', darkWebRoutes);                // /dark-web/* — Phase 5 #4 Ahmia indexed search
v1.route('/', pasteMonitorRoutes);           // /paste/* — Phase 5 #5 paste-site monitoring (GitHub Gist firehose)
v1.route('/', connectorRoutes);              // /connectors/* — A2 of declarative feed-connector engine

export default v1;
