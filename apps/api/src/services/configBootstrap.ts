/**
 * Config Bootstrap — Seeds built-in feeds, API keys, and services
 *
 * Runs on server startup. Uses INSERT ... ON CONFLICT DO UPDATE so it
 * always applies the latest definitions (descriptions, secret flags,
 * test endpoints, placeholders). User-editable fields like `enabled`
 * for feeds are NOT overwritten.
 *
 * After upserting, removes stale non-custom duplicates whose source
 * or name matches a built-in entry but has a different id.
 */

import { and, db, eq, inArray, notInArray, or } from '@rinjani/db';
import { feedsConfig, apiKeySlots, servicesConfig } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('ConfigBootstrap');

// ============================================================================
// Built-in Feed Definitions
// ============================================================================

const BUILTIN_FEEDS = [
    {
        id: 'nvd', name: 'NIST NVD', source: 'nvd',
        description: 'National Vulnerability Database — CVE/CPE entries via REST API. Rate: 5 req/30s (with key), 5 req/30s (without). Docs: https://nvd.nist.gov/developers',
        cron: '0 2 * * *', category: 'threat-feeds',
        requiresApiKey: 'nvd',
        url: process.env.CVE_BASE_URL || 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        authHeader: 'apiKey', authKeyRef: 'CVE_API_KEY', format: 'json' as const,
    },
    {
        id: 'cisa', name: 'CISA KEV', source: 'cisa',
        description: 'Known Exploited Vulnerabilities catalog — no auth required. Updates daily. Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        cron: '0 * * * *', category: 'threat-feeds',
        url: process.env.CISA_CATALOG_URL || 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        format: 'json' as const,
    },
    {
        id: 'otx', name: 'AlienVault OTX', source: 'otx',
        description: 'Open Threat Exchange — pulses with IOCs (IPs, domains, URLs, hashes). Header: X-OTX-API-KEY. Docs: https://otx.alienvault.com/api',
        cron: '*/15 * * * *', category: 'threat-feeds',
        requiresApiKey: 'alienvault',
        url: process.env.ALIENVAULT_BASE_URL || 'https://otx.alienvault.com',
        authHeader: 'X-OTX-API-KEY', authKeyRef: 'ALIENVAULT_API_KEY', format: 'json' as const,
    },
    {
        id: 'misp', name: 'MISP (GSMA T-ISAC)', source: 'misp',
        description: 'Malware Information Sharing Platform — structured events & attributes. Header: Authorization. Docs: https://www.misp-project.org/openapi/',
        cron: '0 */8 * * *', category: 'threat-feeds',
        requiresApiKey: 'misp',
        url: process.env.MISP_URL || 'https://misp.gsma.com',
        authHeader: 'Authorization', authKeyRef: 'MISP_API_KEY', format: 'json' as const,
    },
    {
        id: 'mitre', name: 'MITRE ATT&CK', source: 'mitre',
        description: 'Adversarial Tactics, Techniques & Common Knowledge — STIX 2.1 bundles. No auth required. Docs: https://attack.mitre.org/resources/working-with-attack/',
        cron: '0 4 * * 0', category: 'threat-feeds',
        url: process.env.MITRE_ATLAS_URL || 'https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json',
        format: 'stix' as const,
    },
    {
        id: 'abusessl', name: 'Abuse.ch SSL Blacklist', source: 'abusessl',
        description: 'SSL certificate blacklist for C2 detection — CSV of SHA1 fingerprints & IPs. No auth required. Docs: https://sslbl.abuse.ch/',
        cron: '30 */6 * * *', category: 'threat-feeds',
        url: process.env.ABUSESSL_URL || 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
        format: 'csv' as const,
    },
    {
        id: 'threatfox', name: 'ThreatFox IOCs', source: 'threatfox',
        description: 'IOC sharing by Abuse.ch — malware C2, payload URLs. POST to /api/v1/ with auth_key in body. Docs: https://threatfox.abuse.ch/api/',
        cron: '0 */6 * * *', category: 'threat-feeds',
        requiresApiKey: 'threatfox',
        url: 'https://threatfox-api.abuse.ch/api/v1/',
        authHeader: 'Auth-Key', authKeyRef: 'ABUSECH_API_KEY', format: 'json' as const,
    },
    {
        id: 'malpedia', name: 'Malpedia', source: 'malpedia',
        description: 'Malware encyclopedia — families, actors, YARA rules. Empty key = TLP:WHITE only. Header: Authorization. Docs: https://malpedia.caad.fkie.fraunhofer.de/api/doc',
        cron: '0 0 * * 1', category: 'threat-feeds',
        url: 'https://malpedia.caad.fkie.fraunhofer.de/api',
        authHeader: 'Authorization', authKeyRef: 'MALPEDIA_AUTH_KEY', format: 'json' as const,
    },
    {
        id: 'malwarebazaar', name: 'MalwareBazaar', source: 'malwarebazaar',
        description: 'Malware sample sharing by Abuse.ch — hashes, tags, signatures. POST API. Docs: https://bazaar.abuse.ch/api/',
        cron: '45 */6 * * *', category: 'threat-feeds',
        requiresApiKey: 'abusech',
        url: 'https://mb-api.abuse.ch/api/v1/',
        authHeader: 'Auth-Key', authKeyRef: 'ABUSECH_API_KEY', format: 'json' as const,
    },
    {
        id: 'openphish', name: 'OpenPhish', source: 'openphish',
        description: 'Phishing URL intelligence — plain text list of active phishing URLs. No auth required. Docs: https://openphish.com/',
        cron: '0 */4 * * *', category: 'threat-feeds',
        url: 'https://openphish.com/feed.txt', format: 'text' as const,
    },
    {
        id: 'urlhaus', name: 'URLhaus', source: 'urlhaus',
        description: 'Malicious URL database by Abuse.ch — active malware distribution sites. POST API. Docs: https://urlhaus.abuse.ch/api/',
        cron: '15 */6 * * *', category: 'threat-feeds',
        requiresApiKey: 'urlhaus',
        url: 'https://urlhaus-api.abuse.ch/v1/',
        authHeader: 'Auth-Key', authKeyRef: 'ABUSECH_API_KEY', format: 'json' as const,
    },
    {
        id: 'mispgalaxy', name: 'MISP Galaxy', source: 'mispgalaxy',
        description: 'Threat actor enrichment from MISP Galaxy clusters — aliases, countries, motivations. No auth required. Docs: https://www.misp-galaxy.org/',
        cron: '0 5 * * *', category: 'threat-feeds',
        url: 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json',
        format: 'json' as const,
    },
    {
        id: 'cve-enrichment', name: 'CVE Enrichment', source: 'cve-enrichment',
        description: 'Backfills CVSS scores and published dates for CVEs ingested from CISA KEV. Runs daily after NVD sync.',
        cron: '0 3 * * *', category: 'enrichment',
        url: process.env.CVE_BASE_URL || 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        requiresApiKey: 'nvd',
        authHeader: 'apiKey', authKeyRef: 'CVE_API_KEY', format: 'json' as const,
    },
    {
        id: 'all-feeds', name: 'All Feeds Combined', source: 'all',
        description: 'Sync all threat intelligence feeds in a single scheduled run. Comprehensive coverage across all sources.',
        cron: '*/30 * * * *', category: 'threat-feeds',
        format: 'json' as const,
    },
    {
        id: 'external-datasets', name: 'OpenCTI Reference Datasets', source: 'external',
        description: 'Sectors, geography, and company reference data from OpenCTI community datasets. No auth required.',
        cron: '0 0 1 * *', category: 'reference',
        url: process.env.EXTERNAL_SECTORS_URL || 'https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json',
        format: 'json' as const,
    },
];

// ============================================================================
// Built-in API Key Slot Definitions
// ============================================================================

const BUILTIN_API_KEYS = [
    { id: 'nvd', name: 'NIST NVD API Key', provider: 'NIST', envVar: 'CVE_API_KEY', testEndpoint: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1', authHeaderName: 'apiKey' },
    { id: 'virustotal', name: 'VirusTotal API Key', provider: 'VirusTotal', envVar: 'VIRUSTOTAL_API_KEY', testEndpoint: 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', authHeaderName: 'x-apikey' },
    { id: 'virustotal-livehunt', name: 'VirusTotal LiveHunt Key', provider: 'VirusTotal', envVar: 'VIRUSTOTAL_LIVEHUNT_API_KEY', testEndpoint: 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', authHeaderName: 'x-apikey' },
    { id: 'alienvault', name: 'AlienVault OTX API Key', provider: 'AlienVault', envVar: 'ALIENVAULT_API_KEY', testEndpoint: 'https://otx.alienvault.com/api/v1/user/me', authHeaderName: 'X-OTX-API-KEY' },
    { id: 'misp', name: 'MISP Auth Key', provider: 'MISP', envVar: 'MISP_API_KEY', testEndpoint: (process.env.MISP_URL || 'https://misp.gsma.com') + '/servers/getVersion.json', authHeaderName: 'Authorization' },
    // RiskIQ / PassiveTotal removed — service deprecated, retiring Aug 2026 (Microsoft acquisition)
    { id: 'abuseipdb', name: 'AbuseIPDB API Key', provider: 'AbuseIPDB', envVar: 'ABUSEIPDB_API_KEY', testEndpoint: 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90', authHeaderName: 'Key' },
    { id: 'ipinfo', name: 'IPinfo Token', provider: 'IPinfo', envVar: 'IPINFO_API_KEY', testEndpoint: 'https://ipinfo.io/8.8.8.8', authHeaderName: '?token' },
    { id: 'google-safebrowsing', name: 'Google Safe Browsing', provider: 'Google', envVar: 'GOOGLE_SAFE_BROWSING_API_KEY', testEndpoint: 'https://safebrowsing.googleapis.com/v4/threatLists', authHeaderName: '?key' },
    { id: 'exa', name: 'Exa Search API Key', provider: 'Exa', envVar: 'EXA_API_KEY', testEndpoint: 'https://api.exa.ai/search', authHeaderName: 'x-api-key' },
    { id: 'threatfox', name: 'ThreatFox Auth Key', provider: 'Abuse.ch', envVar: 'ABUSECH_API_KEY', testEndpoint: 'https://threatfox-api.abuse.ch/api/v1/', authHeaderName: 'Auth-Key' },
    { id: 'urlhaus', name: 'URLhaus Auth Key', provider: 'Abuse.ch', envVar: 'ABUSECH_API_KEY', testEndpoint: 'https://urlhaus-api.abuse.ch/v1/', authHeaderName: 'Auth-Key' },
    { id: 'abusech', name: 'Abuse.ch API Key', provider: 'Abuse.ch', envVar: 'ABUSECH_API_KEY', testEndpoint: 'https://mb-api.abuse.ch/api/v1/', authHeaderName: 'Auth-Key' },
    { id: 'malpedia', name: 'Malpedia Auth Key', provider: 'Malpedia', envVar: 'MALPEDIA_AUTH_KEY', testEndpoint: 'https://malpedia.caad.fkie.fraunhofer.de/api/get/version', authHeaderName: 'Bearer' },
    { id: 'google-gemini', name: 'Gemini AI', provider: 'Google', envVar: 'GOOGLE_API_KEY', testEndpoint: 'https://generativelanguage.googleapis.com/v1beta/models', authHeaderName: '?key' },
    { id: 'openrouter', name: 'OpenRouter', provider: 'OpenRouter', envVar: 'OPENROUTER_API_KEY', testEndpoint: 'https://openrouter.ai/api/v1/models', authHeaderName: 'Bearer' },
    { id: 'shodan', name: 'Shodan API Key', provider: 'Shodan', envVar: 'SHODAN_API_KEY', testEndpoint: 'https://api.shodan.io/api-info', authHeaderName: '?key' },
    { id: 'zoomeye', name: 'ZoomEye API Key', provider: 'ZoomEye', envVar: 'ZOOMEYE_API_KEY', testEndpoint: 'https://api.zoomeye.ai/v2/userinfo', authHeaderName: 'API-KEY' },
];

// ============================================================================
// Built-in Service Definitions
// secret: true  → password field, masked in API response
// secret: false → plain text field, actual value visible in modal
// ============================================================================

const BUILTIN_SERVICES = [
    {
        id: 'postgresql', name: 'PostgreSQL',
        envVars: [
            { key: 'DATABASE_URL', label: 'Connection URL', secret: false, placeholder: 'postgresql://user:pass@localhost:5432/dbname' },
            { key: 'POSTGRES_USER', label: 'Username', secret: false, placeholder: 'postgres' },
            { key: 'POSTGRES_PASSWORD', label: 'Password', secret: true, placeholder: '••••••••' },
            { key: 'POSTGRES_DB', label: 'Database Name', secret: false, placeholder: 'rinjani_v3' },
        ],
    },
    {
        id: 'opensearch', name: 'OpenSearch',
        envVars: [
            { key: 'OPENSEARCH_URL', label: 'Cluster URL', secret: false, placeholder: 'http://localhost:9200' },
            { key: 'OPENSEARCH_USERNAME', label: 'Username', secret: false, placeholder: 'admin' },
            { key: 'OPENSEARCH_PASSWORD', label: 'Password', secret: true, placeholder: '••••••••' },
        ],
    },
    {
        id: 'neo4j', name: 'Neo4j Graph Database',
        envVars: [
            { key: 'NEO4J_URI', label: 'Bolt URI', secret: false, placeholder: 'bolt://localhost:7687' },
            { key: 'NEO4J_USER', label: 'Username', secret: false, placeholder: 'neo4j' },
            { key: 'NEO4J_PASSWORD', label: 'Password', secret: true, placeholder: '••••••••' },
        ],
    },
    {
        id: 'redis', name: 'Redis',
        envVars: [
            { key: 'REDIS_URL', label: 'Connection URL', secret: false, placeholder: 'redis://localhost:6379' },
        ],
    },
    {
        id: 'minio', name: 'MinIO Object Storage',
        envVars: [
            { key: 'MINIO_USER', label: 'Access Key', secret: false, placeholder: 'minioadmin' },
            { key: 'MINIO_PASSWORD', label: 'Secret Key', secret: true, placeholder: '••••••••' },
            { key: 'MINIO_BUCKET', label: 'Default Bucket', secret: false, placeholder: 'v3-files' },
        ],
    },
    {
        id: 'rabbitmq', name: 'RabbitMQ',
        envVars: [
            { key: 'RABBITMQ_USER', label: 'Username', secret: false, placeholder: 'admin' },
            { key: 'RABBITMQ_PASSWORD', label: 'Password', secret: true, placeholder: '••••••••' },
        ],
    },
    {
        id: 'google-gemini', name: 'Google Gemini (AI)',
        envVars: [
            { key: 'GOOGLE_API_KEY', label: 'Google AI Platform Key', secret: true, placeholder: 'AIzaSy...' },
            { key: 'GEMINI_API_KEY', label: 'Gemini API Key', secret: true, placeholder: 'AIzaSy...' },
        ],
    },
    {
        id: 'openrouter', name: 'OpenRouter (AI)',
        envVars: [
            { key: 'OPENROUTER_API_KEY', label: 'API Key', secret: true, placeholder: 'sk-or-v1-...' },
        ],
    },
    {
        id: 'riskiq', name: 'RiskIQ / PassiveTotal',
        envVars: [
            { key: 'RISKIQ_USER', label: 'Username (email)', secret: false, placeholder: 'user@example.com' },
            { key: 'RISKIQ_PASSWORD', label: 'Password', secret: true, placeholder: '••••••••' },
            { key: 'RISKIQ_BASE_URL', label: 'API Base URL', secret: false, placeholder: 'https://api.riskiq.net/pt/v2' },
        ],
    },
    {
        id: 'shodan', name: 'Shodan',
        envVars: [
            { key: 'SHODAN_API_KEY', label: 'API Key', secret: true, placeholder: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
        ],
    },
    {
        id: 'zoomeye', name: 'ZoomEye',
        envVars: [
            { key: 'ZOOMEYE_API_KEY', label: 'API Key', secret: true, placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
        ],
    },
    // ── Platform Services (optional) ──────────────────────────────────────
    {
        id: 'vault', name: 'HashiCorp Vault',
        envVars: [
            { key: 'VAULT_ADDR', label: 'Vault Address', secret: false, placeholder: 'http://localhost:8200' },
            { key: 'VAULT_ROOT_TOKEN', label: 'Root Token', secret: true, placeholder: 'hvs.xxxxx' },
        ],
    },
    {
        id: 'keycloak', name: 'Keycloak SSO',
        envVars: [
            { key: 'KEYCLOAK_URL', label: 'Keycloak URL', secret: false, placeholder: 'http://localhost:8443' },
            { key: 'KEYCLOAK_REALM', label: 'Realm', secret: false, placeholder: 'rinjani' },
            { key: 'KEYCLOAK_CLIENT_ID', label: 'Client ID', secret: false, placeholder: 'rinjani-api' },
            { key: 'KEYCLOAK_CLIENT_SECRET', label: 'Client Secret', secret: true, placeholder: '••••••••' },
        ],
    },
];

// ============================================================================
// Bootstrap Function — UPSERT + DEDUP
// ============================================================================

export async function ensureBuiltInIntegrations(): Promise<void> {
    const now = new Date();
    let feedCount = 0, keyCount = 0, svcCount = 0;

    // Collect canonical IDs for dedup cleanup
    const canonicalFeedIds = BUILTIN_FEEDS.map(f => f.id);
    const canonicalKeyIds = BUILTIN_API_KEYS.map(k => k.id);
    const canonicalSvcIds = BUILTIN_SERVICES.map(s => s.id);

    // ── Feeds (upsert: update description/url/auth but preserve user's enabled toggle) ──
    for (const f of BUILTIN_FEEDS) {
        try {
            await db.insert(feedsConfig).values({
                id: f.id,
                name: f.name,
                source: f.source,
                description: f.description,
                cron: f.cron,
                enabled: true,
                category: f.category,
                requiresApiKey: f.requiresApiKey ?? null,
                isCustom: false,
                url: f.url ?? null,
                authHeader: f.authHeader ?? null,
                authKeyRef: f.authKeyRef ?? null,
                format: f.format ?? null,
                createdAt: now,
                updatedAt: now,
            }).onConflictDoUpdate({
                target: feedsConfig.id,
                set: {
                    name: f.name,
                    source: f.source,
                    description: f.description,
                    url: f.url ?? null,
                    authHeader: f.authHeader ?? null,
                    authKeyRef: f.authKeyRef ?? null,
                    format: f.format ?? null,
                    requiresApiKey: f.requiresApiKey ?? null,
                    updatedAt: now,
                    // NOTE: enabled, cron, category NOT overwritten — user controls these
                },
            });
            feedCount++;
        } catch (err) {
            log.warn(`Failed to seed feed ${f.id}`, { error: (err as Error).message });
        }
    }

    // ── Remove stale duplicate feed entries ──
    // Delete any non-custom feed whose id is NOT in the canonical list
    try {
        const deleted = await db.delete(feedsConfig)
            .where(and(
                eq(feedsConfig.isCustom, false),
                notInArray(feedsConfig.id, canonicalFeedIds),
            ))
            .returning({ id: feedsConfig.id, name: feedsConfig.name });
        if (deleted.length > 0) {
            log.info('Removed stale duplicate feeds', {
                count: deleted.length,
                removed: deleted.map(d => d.name),
            });
        }
    } catch (err) {
        log.warn('Failed to clean stale feeds', { error: (err as Error).message });
    }

    // ── API Key Slots (upsert + dedup) ──
    for (const k of BUILTIN_API_KEYS) {
        try {
            await db.insert(apiKeySlots).values({
                id: k.id,
                name: k.name,
                provider: k.provider,
                envVar: k.envVar,
                testEndpoint: k.testEndpoint ?? null,
                authHeaderName: k.authHeaderName ?? null,
                isCustom: false,
                createdAt: now,
                updatedAt: now,
            }).onConflictDoUpdate({
                target: apiKeySlots.id,
                set: {
                    name: k.name,
                    provider: k.provider,
                    envVar: k.envVar,
                    testEndpoint: k.testEndpoint ?? null,
                    authHeaderName: k.authHeaderName ?? null,
                    updatedAt: now,
                },
            });
            keyCount++;
        } catch (err) {
            log.warn(`Failed to seed API key ${k.id}`, { error: (err as Error).message });
        }
    }

    // ── Remove stale duplicate API key slots ──
    try {
        const deleted = await db.delete(apiKeySlots)
            .where(and(
                eq(apiKeySlots.isCustom, false),
                notInArray(apiKeySlots.id, canonicalKeyIds),
            ))
            .returning({ id: apiKeySlots.id, name: apiKeySlots.name });
        if (deleted.length > 0) {
            log.info('Removed stale duplicate API key slots', {
                count: deleted.length,
                removed: deleted.map(d => d.name),
            });
        }
    } catch (err) {
        log.warn('Failed to clean stale API keys', { error: (err as Error).message });
    }

    // ── Services (upsert + dedup) ──
    for (const s of BUILTIN_SERVICES) {
        try {
            await db.insert(servicesConfig).values({
                id: s.id,
                name: s.name,
                envVars: s.envVars,
                isCustom: false,
                createdAt: now,
                updatedAt: now,
            }).onConflictDoUpdate({
                target: servicesConfig.id,
                set: {
                    name: s.name,
                    envVars: s.envVars,
                    updatedAt: now,
                },
            });
            svcCount++;
        } catch (err) {
            log.warn(`Failed to seed service ${s.id}`, { error: (err as Error).message });
        }
    }

    // ── Remove stale duplicate service entries ──
    try {
        const deleted = await db.delete(servicesConfig)
            .where(and(
                eq(servicesConfig.isCustom, false),
                notInArray(servicesConfig.id, canonicalSvcIds),
            ))
            .returning({ id: servicesConfig.id, name: servicesConfig.name });
        if (deleted.length > 0) {
            log.info('Removed stale duplicate services', {
                count: deleted.length,
                removed: deleted.map(d => d.name),
            });
        }
    } catch (err) {
        log.warn('Failed to clean stale services', { error: (err as Error).message });
    }

    log.info('Built-in integrations ensured', {
        feeds: feedCount,
        apiKeys: keyCount,
        services: svcCount,
    });
}
