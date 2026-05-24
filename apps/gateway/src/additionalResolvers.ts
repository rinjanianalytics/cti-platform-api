/**
 * Additional Resolvers — REST→GraphQL Bridging
 *
 * These resolvers extend the stitched gateway schema with fields
 * that delegate to the upstream REST API. They provide a GraphQL
 * interface for data not yet natively in the Pothos subgraph.
 *
 * Categories:
 *   - Stats & Monitoring (health, freshness, ops ingestion)
 *   - Configuration (feeds, API keys, services)
 *   - Intelligence (MITRE matrix, IOC enrichment, alerts)
 *   - Graph Exploration (Neo4j: attack tree, IOC pivot, search)
 *   - Admin (users, audit, queues)
 */

// In unified mode, the REST API is served on the same port as the gateway
const GATEWAY_PORT = process.env.GATEWAY_PORT || '4000';
const CTI_API_URL = process.env.CTI_API_URL || `http://localhost:${GATEWAY_PORT}`;

// ============================================================================
// Helper: Fetch from upstream REST API
// ============================================================================

async function restFetch<T = unknown>(
    path: string,
    opts?: { method?: string; body?: unknown; headers?: Record<string, string> },
): Promise<T> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(opts?.headers || {}),
    };

    const res = await fetch(`${CTI_API_URL}${path}`, {
        method: opts?.method || 'GET',
        headers,
        body: opts?.body ? JSON.stringify(opts.body) : undefined,
    });

    if (!res.ok) {
        throw new Error(`REST ${res.status} ${res.statusText} — ${path}`);
    }

    const json = await res.json() as Record<string, unknown>;
    // The API wraps most responses in { data: ... } or { success: true, data: ... }
    return (json.data ?? json) as T;
}

/** Wrap fetch with fallback so a single failing resolver doesn't crash the query */
async function safeFetch<T>(path: string, fallback: T, opts?: Parameters<typeof restFetch>[1]): Promise<T> {
    try {
        return await restFetch<T>(path, opts);
    } catch {
        return fallback;
    }
}

// ============================================================================
// Resolvers
// ============================================================================

const resolvers = {
    Query: {
        // ── Stats & Monitoring ──────────────────────────────────────────────
        systemHealth: async () => {
            const data = await safeFetch<Record<string, unknown>>('/health', {});
            return {
                status: data.status || 'unknown',
                uptime: data.uptime || null,
                timestamp: data.timestamp || new Date().toISOString(),
                services: data.services || data.checks || null,
            };
        },

        platformStats: async () => safeFetch('/v1/stats', null),

        freshness: async () => safeFetch('/v1/stats/freshness', null),

        feedHealth: async () => safeFetch('/v1/monitoring/feeds', null),

        opsIngestion: async () => safeFetch('/v1/ops/ingestion', null),

        opsEnrichment: async () => safeFetch('/v1/ops/enrichment', null),

        distribution: async () => safeFetch('/v1/stats/distribution', []),

        sourceBreakdown: async () => safeFetch('/v1/stats/source-breakdown', []),

        severityTrend: async (_: unknown, args: { days?: number }) =>
            safeFetch(`/v1/stats/severity-trend?days=${args.days || 30}`, []),

        iocGrowth: async (_: unknown, args: { days?: number }) =>
            safeFetch(`/v1/monitoring/metrics/growth?days=${args.days || 30}`, { iocs: [] }),

        // ── Configuration ───────────────────────────────────────────────────
        feeds: async () => safeFetch('/v1/config/feeds', []),
        apiKeys: async () => safeFetch('/v1/config/api-keys', []),
        services: async () => safeFetch('/v1/config/services', []),
        integrations: async () => safeFetch('/v1/config/integrations', []),

        // ── MITRE ATT&CK ────────────────────────────────────────────────────
        mitreMatrix: async () => safeFetch('/v1/mitre/matrix', null),

        mitreTactics: async () => {
            const result = await safeFetch<{ data?: unknown[] }>('/v1/mitre/tactics', { data: [] });
            return (result as Record<string, unknown>)?.data || result || [];
        },

        // ── Alerts ──────────────────────────────────────────────────────────
        alerts: async (_: unknown, args: { page?: number; limit?: number; severity?: string; unread?: boolean }) => {
            const params = new URLSearchParams();
            if (args.page) params.set('page', String(args.page));
            if (args.limit) params.set('pageSize', String(args.limit));
            if (args.severity) params.set('severity', args.severity);
            if (args.unread) params.set('unread', 'true');
            return safeFetch(`/v1/alerts?${params}`, { alerts: [], pagination: {} });
        },

        unreadAlertCount: async () => safeFetch('/v1/alerts/unread/count', { unread: 0, highSeverity: 0 }),

        // ── Audit Logs ──────────────────────────────────────────────────────
        auditLogs: async (_: unknown, args: { limit?: number; entityType?: string; action?: string }) => {
            const params = new URLSearchParams();
            if (args.limit) params.set('limit', String(args.limit));
            if (args.entityType) params.set('entityType', args.entityType);
            if (args.action) params.set('action', args.action);
            return safeFetch(`/admin/audit?${params}`, { entries: [], total: 0 });
        },

        auditStats: async (_: unknown, args: { days?: number }) =>
            safeFetch(`/admin/audit/stats${args.days ? `?days=${args.days}` : ''}`, null),

        // ── Admin: Users ────────────────────────────────────────────────────
        users: async (_: unknown, args: { role?: string; search?: string; page?: number; limit?: number }) => {
            const params = new URLSearchParams();
            if (args.role) params.set('role', args.role);
            if (args.search) params.set('search', args.search);
            if (args.page) params.set('page', String(args.page));
            if (args.limit) params.set('limit', String(args.limit));
            return safeFetch(`/admin/users?${params}`, { users: [], total: 0 });
        },

        roles: async () => safeFetch('/admin/users/roles/list', { roles: [], permissionModules: [] }),

        // ── Admin: Queues ───────────────────────────────────────────────────
        queueStats: async () => safeFetch('/admin/stats', null),

        // ── Admin: Settings ─────────────────────────────────────────────────
        settings: async () => safeFetch('/admin/config/settings', {}),

        // ── Graph Exploration (Neo4j via REST) ──────────────────────────────
        // Note: graphSearch, graphExpand, graphShortestPath, attackTree, iocPivot
        // are already in the upstream Pothos schema — only add NEW queries here.
        neo4jHealth: async () => safeFetch('/v1/graph/neo4j/health', null),

        neo4jStats: async () => safeFetch('/v1/graph/neo4j/stats', null),

        relatedActors: async (_: unknown, args: { actor: string; minShared?: number }) =>
            safeFetch(`/v1/graph/neo4j/related-actors/${encodeURIComponent(args.actor)}?minShared=${args.minShared || 1}`, { actors: [] }),

        // ── Intelligence ────────────────────────────────────────────────────
        enrichIOC: async (_: unknown, args: { value: string; sources?: string[]; refresh?: boolean }) => {
            const params = new URLSearchParams();
            if (args.sources?.length) params.set('sources', args.sources.join(','));
            if (args.refresh) params.set('refresh', 'true');
            const qs = params.toString();
            return safeFetch(`/v1/intelligence/ioc/${encodeURIComponent(args.value)}${qs ? `?${qs}` : ''}`, null);
        },

        actorIntelligence: async (_: unknown, args: { actorId: string }) =>
            safeFetch(`/v1/intelligence/actor/${encodeURIComponent(args.actorId)}`, null),

        cveIntelligence: async (_: unknown, args: { cveId: string }) =>
            safeFetch(`/v1/intelligence/cve/${encodeURIComponent(args.cveId)}`, null),

        // ── Playbooks ───────────────────────────────────────────────────────
        playbooks: async (_: unknown, args: { enabledOnly?: boolean }) =>
            safeFetch(`/v1/playbooks${args.enabledOnly ? '?enabled=true' : ''}`, { items: [], count: 0 }),

        // ── Webhooks ────────────────────────────────────────────────────────
        webhooks: async () => safeFetch('/v1/webhooks', { subscriptions: [], count: 0 }),
    },

    // Mutations — wrapping key write endpoints
    Mutation: {
        createAlert: async (_: unknown, args: { severity?: string; type?: string; title: string; message: string }) =>
            restFetch('/v1/alerts', { method: 'POST', body: args }),

        markAlertRead: async (_: unknown, args: { id: string }) =>
            safeFetch(`/v1/alerts/${args.id}/read`, null, { method: 'POST' }),

        markAllAlertsRead: async () =>
            restFetch('/v1/alerts/read-all', { method: 'POST' }),

        updateFeed: async (_: unknown, args: { id: string; enabled?: boolean; cron?: string }) =>
            restFetch(`/v1/config/feeds/${args.id}`, { method: 'PUT', body: args }),

        setSetting: async (_: unknown, args: { key: string; value: string }) =>
            restFetch(`/admin/config/settings/${args.key}`, { method: 'PUT', body: { value: args.value } }),

        triggerNeo4jSync: async (_: unknown, args: { syncType?: string }) =>
            restFetch('/v1/graph/neo4j/sync', { method: 'POST', body: { syncType: args.syncType || 'full' } }),
    },

    // JSON scalar — passthrough for untyped data
    JSON: {
        __serialize: (value: unknown) => value,
        __parseValue: (value: unknown) => value,
        __parseLiteral: () => null,
    },
};

export default resolvers;
