/**
 * Config Management Routes
 * 
 * REST endpoints for managing feeds, API keys, and service connections.
 * Supports both built-in defaults (edit only) and custom entries (full CRUD).
 */

import { Hono } from 'hono';
import {
    listFeeds, updateFeed, addCustomFeed, deleteCustomFeed,
    listApiKeys, updateApiKey, addCustomApiKey, deleteCustomApiKey, testApiKey,
    listServices, updateService, addCustomService, deleteCustomService,
    getFeedById, getFeedSyncHistory, testFeedConnectivity,
} from '../../services/configStore';
import { ValidationError, NotFoundError } from '../../lib/errors';
import { feedSyncQueue } from '../../queues/definitions';
import {
    AddFeedSchema, UpdateFeedSchema,
    AddApiKeySchema, UpdateApiKeyValueSchema,
    AddServiceSchema, UpdateServiceSchema,
    FeedSyncTriggerSchema, FeedSyncHistoryQuerySchema,
} from '../../lib/schemas';

const config = new Hono();

// ============================================================================
// FEEDS
// ============================================================================

config.get('/config/feeds', async (c) => {
    const feeds = await listFeeds();
    return c.json({ data: feeds });
});

config.post('/config/feeds', async (c) => {
    const body = AddFeedSchema.parse(await c.req.json().catch(() => ({})));
    const feed = await addCustomFeed(body);
    return c.json({ data: feed }, 201);
});

config.put('/config/feeds/:id', async (c) => {
    const { id } = c.req.param();
    const body = UpdateFeedSchema.parse(await c.req.json().catch(() => ({})));
    const updated = await updateFeed(id, body);
    if (!updated) throw new NotFoundError('Feed', id);
    return c.json({ data: updated });
});

config.delete('/config/feeds/:id', async (c) => {
    const { id } = c.req.param();
    const ok = await deleteCustomFeed(id);
    if (!ok) throw new NotFoundError('Feed', id);
    return c.json({ data: { id, deleted: true } });
});

/** POST /config/feeds/:id/sync — Trigger manual feed sync (MISP/IntelOwl inspired) */
config.post('/config/feeds/:id/sync', async (c) => {
    const { id } = c.req.param();
    const body = FeedSyncTriggerSchema.parse(await c.req.json().catch(() => ({})));
    const feed = await getFeedById(id);
    if (!feed) throw new NotFoundError('Feed', id);

    const job = await feedSyncQueue.add(`manual-sync-${feed.source}`, {
        source: feed.source,
        options: { ...(body.force ? { force: true } : {}) },
    });

    return c.json({
        data: {
            jobId: job.id,
            feedId: id,
            feedName: feed.name,
            message: `Sync job queued for ${feed.name}`,
        },
    }, 202);
});

/** GET /config/feeds/:id/history — Feed sync run history */
config.get('/config/feeds/:id/history', async (c) => {
    const { id } = c.req.param();
    const { limit } = FeedSyncHistoryQuerySchema.parse(c.req.query());
    const feed = await getFeedById(id);
    if (!feed) throw new NotFoundError('Feed', id);

    const history = await getFeedSyncHistory(id, limit);
    return c.json({ data: { feedId: id, feedName: feed.name, runs: history } });
});

/** POST /config/feeds/:id/test — Test feed connectivity */
config.post('/config/feeds/:id/test', async (c) => {
    const { id } = c.req.param();
    const result = await testFeedConnectivity(id);
    return c.json({ data: result });
});


config.get('/config/api-keys', async (c) => {
    const keys = await listApiKeys();
    return c.json({ data: keys });
});

config.post('/config/api-keys', async (c) => {
    const body = AddApiKeySchema.parse(await c.req.json().catch(() => ({})));
    const { value, ...slotData } = body;
    const slot = await addCustomApiKey(slotData, value);
    return c.json({ data: slot }, 201);
});

config.put('/config/api-keys/:id', async (c) => {
    const { id } = c.req.param();
    const { value } = UpdateApiKeyValueSchema.parse(await c.req.json().catch(() => ({})));
    const ok = await updateApiKey(id, value.trim());
    if (!ok) throw new NotFoundError('API key', id);
    return c.json({ data: { id, updated: true } });
});

config.delete('/config/api-keys/:id', async (c) => {
    const { id } = c.req.param();
    const ok = await deleteCustomApiKey(id);
    if (!ok) throw new NotFoundError('API key', id);
    return c.json({ data: { id, deleted: true } });
});

config.post('/config/api-keys/:id/test', async (c) => {
    const { id } = c.req.param();
    const result = await testApiKey(id);
    return c.json({ data: result });
});

// ============================================================================
// SERVICES
// ============================================================================

config.get('/config/services', async (c) => {
    const services = await listServices();
    return c.json({ data: services });
});

config.post('/config/services', async (c) => {
    const body = AddServiceSchema.parse(await c.req.json().catch(() => ({})));
    const { values, ...svcData } = body;
    const svc = await addCustomService(svcData, values);
    return c.json({ data: svc }, 201);
});

config.put('/config/services/:id', async (c) => {
    const { id } = c.req.param();
    const updates = UpdateServiceSchema.parse(await c.req.json().catch(() => ({}))) as Record<string, string>;
    const ok = await updateService(id, updates);
    if (!ok) throw new NotFoundError('Service', id);
    return c.json({ data: { id, updated: true } });
});

config.delete('/config/services/:id', async (c) => {
    const { id } = c.req.param();
    const ok = await deleteCustomService(id);
    if (!ok) throw new NotFoundError('Service', id);
    return c.json({ data: { id, deleted: true } });
});

// ============================================================================
// UNIFIED INTEGRATIONS (aggregated view)
// ============================================================================

const SERVICE_ICONS: Record<string, string> = {
    postgresql: '🐘', redis: '⚡', opensearch: '🔍', neo4j: '🕸️', misp: '🛡️', alienvault: '👽',
    minio: '📦', rabbitmq: '🐇', 'google-gemini': '🤖', openrouter: '🤖', riskiq: '🔍',
    shodan: '🔎', zoomeye: '👁️', vault: '🔐', keycloak: '🔑',
};

const FEED_ICONS: Record<string, string> = {
    otx: '👽', cisa: '🏛️', nvd: '📋', all: '🔄', 'cve-enrichment': '🔬',
    abusessl: '🔒', threatfox: '🦊', urlhaus: '🔗', malwarebazaar: '💀',
    openphish: '🎣', mitre: '⚔️', mispgalaxy: '🌌', nexus: '🌐',
    malpedia: '📚', external: '📊',
};

const PROVIDER_ICONS: Record<string, string> = {
    VirusTotal: '🛡️', AlienVault: '👽', MISP: '🛡️', NIST: '🏛️',
    RiskIQ: '🔍', 'Abuse.ch': '🦊', AbuseIPDB: '🚫', Google: '🤖',
    OpenRouter: '🤖', IPinfo: '📍', Exa: '🌐', Malpedia: '📚',
    Shodan: '🔎', ZoomEye: '👁️',
};

// Logo image paths — only for providers with real logo files in public/logos/
const FEED_LOGOS: Record<string, string> = {
    otx: '/logos/alienvault.svg',
    cisa: '/logos/cisa.png',
    nvd: '/logos/nvd.png',
    mitre: '/logos/mitre.png',
    abusessl: '/logos/abusessl.svg',
    threatfox: '/logos/threatfox.svg',
    urlhaus: '/logos/urlhaus.svg',
    malwarebazaar: '/logos/malwarebazaar.svg',
    openphish: '/logos/openphish.png',
    malpedia: '/logos/malpedia.png',
    mispgalaxy: '/logos/misp.png',
};

const SERVICE_LOGOS: Record<string, string> = {
    postgresql: '/logos/postgresql.png',
    redis: '/logos/redis.png',
    opensearch: '/logos/opensearch.png',
    neo4j: '/logos/neo4j.png',
    misp: '/logos/misp.png',
    alienvault: '/logos/alienvault.svg',
    minio: '/logos/minio.svg',
    rabbitmq: '/logos/rabbitmq.svg',
    'google-gemini': '/logos/google.png',
    openrouter: '/logos/openrouter.png',
    shodan: '/logos/shodan.png',
    vault: '/logos/vault.svg',
    keycloak: '/logos/keycloak.svg',
};

const PROVIDER_LOGOS: Record<string, string> = {
    VirusTotal: '/logos/virustotal.png',
    AlienVault: '/logos/alienvault.svg',
    MISP: '/logos/misp.png',
    AbuseIPDB: '/logos/abuseipdb.png',
    OpenRouter: '/logos/openrouter.png',
    IPinfo: '/logos/ipinfo.png',
    Exa: '/logos/exa.png',
    Malpedia: '/logos/malpedia.png',
    NIST: '/logos/nist.png',
    Google: '/logos/google.png',
    'Abuse.ch': '/logos/abusech.svg',
    Shodan: '/logos/shodan.png',
};

config.get('/config/integrations', async (c) => {
    const [feeds, apiKeys, services] = await Promise.all([
        listFeeds(), listApiKeys(), listServices(),
    ]);

    const integrations = [
        ...feeds.map(f => ({
            id: f.id,
            name: f.name,
            type: 'feed' as const,
            category: (['custom-api', 'rss', 'financial', 'osint'].includes(f.category)) ? 'custom' : 'threat-feeds',
            description: f.description,
            status: (f.enabled ? 'active' : 'not-connected') as 'active' | 'not-connected' | 'error',
            icon: FEED_ICONS[f.source] || '📡',
            logoUrl: FEED_LOGOS[f.source] || undefined,
            custom: !!f.custom,
            cron: f.cron,
            enabled: f.enabled,
            url: f.url,
            format: f.format,
            requiresApiKey: f.requiresApiKey,
            source: f.source,
            feedCategory: f.category,
            authHeader: f.authHeader,
            authKeyRef: f.authKeyRef,
        })),
        ...apiKeys.map(k => ({
            id: k.id,
            name: k.name,
            type: 'api-key' as const,
            category: 'api-providers',
            description: `${k.provider} — ${k.envVar}`,
            status: (k.configured ? 'active' : 'not-connected') as 'active' | 'not-connected' | 'error',
            icon: PROVIDER_ICONS[k.provider] || '🔑',
            logoUrl: PROVIDER_LOGOS[k.provider] || undefined,
            custom: !!k.custom,
            provider: k.provider,
            envVar: k.envVar,
            maskedValue: k.maskedValue,
            configured: k.configured,
            testEndpoint: k.testEndpoint,
            authHeaderName: k.authHeaderName,
        })),
        ...services.map(s => ({
            id: s.id,
            name: s.name,
            type: 'service' as const,
            category: 'infrastructure',
            description: s.envVars.map(ev => ev.label).join(', '),
            status: (Object.values(s.values).some(v => v && v !== 'null') ? 'active' : 'not-connected') as 'active' | 'not-connected' | 'error',
            icon: SERVICE_ICONS[s.id] || '📦',
            logoUrl: SERVICE_LOGOS[s.id] || undefined,
            custom: !!s.custom,
            envVars: s.envVars,
            values: s.values,
        })),
    ];

    return c.json({ data: integrations });
});

export default config;
