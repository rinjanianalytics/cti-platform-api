/**
 * Config Store — PostgreSQL-backed configuration with Redis KV for settings
 *
 * Feed definitions, API key slot definitions, and service connection configs
 * are now stored in PostgreSQL tables (feeds_config, api_key_slots, services_config).
 *
 * Simple key-value settings (env var overrides) still use Redis for hot-reload.
 */

import { db, eq, sql, rawQuery } from '@rinjani/db';
import { feedsConfig, apiKeySlots, servicesConfig } from '@rinjani/db/schema';
import { connection } from './redis';
import { secrets } from './vault';
import { createLogger } from '../lib/logger';

const log = createLogger('ConfigStore');
const PREFIX = 'rjn:config:';

/**
 * Resolve a secret value using priority: Vault → Redis → env.
 * Used for API key lookups so Vault is automatically preferred when available.
 */
async function resolveSecret(envVar: string): Promise<string | null> {
    // 1. Try Vault (path derived from env var name, e.g. VIRUSTOTAL_API_KEY → api-keys/virustotal-api-key)
    try {
        const vaultPath = `api-keys/${envVar.toLowerCase().replace(/_/g, '-')}`;
        const vaultVal = await secrets.get(vaultPath);
        if (vaultVal) return vaultVal;
    } catch { /* Vault unavailable, continue */ }

    // 2. Fall through to Redis → env (existing getConfig behavior)
    return getConfig(envVar);
}

// ============================================================================
// Core Key-Value CRUD (Redis — for simple settings / env overrides)
// ============================================================================

export async function getConfig(key: string): Promise<string | null> {
    try {
        const val = await connection.get(`${PREFIX}${key}`);
        if (val !== null) return val;
    } catch (err) {
        log.error('Redis read failed, falling back to env', new Error((err as Error).message));
    }
    return process.env[key] || null;
}

export async function setConfig(key: string, value: string): Promise<void> {
    await connection.set(`${PREFIX}${key}`, value);
    log.info('Config updated', { key });
}

export async function deleteConfig(key: string): Promise<void> {
    await connection.del(`${PREFIX}${key}`);
    log.info('Config override removed (reverted to env)', { key });
}

// ============================================================================
// Feed Definitions (PostgreSQL-backed)
// ============================================================================

export type FeedCategory = 'high-frequency' | 'ioc-feeds' | 'knowledge-base' | 'nexus' | 'custom-api' | 'rss' | 'financial' | 'osint';

export interface FeedConfig {
    id: string;
    name: string;
    source: string;
    description: string;
    cron: string;
    enabled: boolean;
    category: FeedCategory;
    requiresApiKey?: string;
    custom?: boolean;
    url?: string;
    authHeader?: string;
    authKeyRef?: string;
    format?: 'json' | 'csv' | 'rss' | 'stix' | 'text';
}

export async function listFeeds(): Promise<FeedConfig[]> {
    const rows = await db.select().from(feedsConfig).orderBy(feedsConfig.name);
    return rows.map(r => ({
        id: r.id,
        name: r.name,
        source: r.source,
        description: r.description,
        cron: r.cron,
        enabled: r.enabled,
        category: r.category as FeedCategory,
        requiresApiKey: r.requiresApiKey ?? undefined,
        custom: r.isCustom,
        url: r.url ?? undefined,
        authHeader: r.authHeader ?? undefined,
        authKeyRef: r.authKeyRef ?? undefined,
        format: r.format as FeedConfig['format'] ?? undefined,
    }));
}

export async function getFeedById(id: string): Promise<FeedConfig | null> {
    const rows = await db.select().from(feedsConfig).where(eq(feedsConfig.id, id)).limit(1);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
        id: r.id, name: r.name, source: r.source, description: r.description,
        cron: r.cron, enabled: r.enabled, category: r.category as FeedCategory,
        requiresApiKey: r.requiresApiKey ?? undefined, custom: r.isCustom,
        url: r.url ?? undefined, authHeader: r.authHeader ?? undefined,
        authKeyRef: r.authKeyRef ?? undefined, format: r.format as FeedConfig['format'] ?? undefined,
    };
}

export async function updateFeed(id: string, updates: {
    cron?: string; enabled?: boolean; name?: string; description?: string;
    url?: string; format?: string; authHeader?: string; authKeyRef?: string;
    category?: string; source?: string;
}): Promise<FeedConfig | null> {
    const existing = await getFeedById(id);
    if (!existing) return null;

    const set: Record<string, unknown> = { updatedAt: new Date() };
    if (updates.cron !== undefined) set.cron = updates.cron;
    if (updates.enabled !== undefined) set.enabled = updates.enabled;
    if (updates.name !== undefined) set.name = updates.name;
    if (updates.description !== undefined) set.description = updates.description;
    if (updates.url !== undefined) set.url = updates.url || null;
    if (updates.format !== undefined) set.format = updates.format || null;
    if (updates.authHeader !== undefined) set.authHeader = updates.authHeader || null;
    if (updates.authKeyRef !== undefined) set.authKeyRef = updates.authKeyRef || null;
    if (updates.category !== undefined) set.category = updates.category;
    if (updates.source !== undefined) set.source = updates.source;

    await db.update(feedsConfig).set(set).where(eq(feedsConfig.id, id));

    // Emit specific log when feed is enabled/disabled
    if (updates.enabled !== undefined) {
        log.info(`Feed ${updates.enabled ? 'ENABLED' : 'DISABLED'}: ${existing.name}`, {
            id, source: existing.source, enabled: updates.enabled,
        });
    }
    log.info('Feed config updated', { id, fields: Object.keys(updates) });
    return getFeedById(id);
}

export async function addCustomFeed(feed: Omit<FeedConfig, 'id' | 'custom'>): Promise<FeedConfig> {
    const id = `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const now = new Date();

    await db.insert(feedsConfig).values({
        id,
        name: feed.name,
        source: feed.source,
        description: feed.description,
        cron: feed.cron,
        enabled: feed.enabled,
        category: feed.category,
        requiresApiKey: feed.requiresApiKey ?? null,
        isCustom: true,
        url: feed.url ?? null,
        authHeader: feed.authHeader ?? null,
        authKeyRef: feed.authKeyRef ?? null,
        format: feed.format ?? null,
        createdAt: now,
        updatedAt: now,
    });

    log.info('Custom feed added', { id, name: feed.name });
    return (await getFeedById(id))!;
}

export async function deleteCustomFeed(id: string): Promise<boolean> {
    const feed = await getFeedById(id);
    if (!feed || !feed.custom) return false;
    await db.delete(feedsConfig).where(eq(feedsConfig.id, id));
    log.info('Custom feed deleted', { id });
    return true;
}

// ============================================================================
// API Key Definitions (PostgreSQL-backed)
// ============================================================================

export interface ApiKeyConfig {
    id: string;
    name: string;
    provider: string;
    envVar: string;
    maskedValue: string | null;
    configured: boolean;
    testEndpoint?: string;
    custom?: boolean;
    authHeaderName?: string;
}

function maskValue(val: string | null): string | null {
    if (!val || val.length < 8) return val ? '****' : null;
    return `${'*'.repeat(val.length - 4)}${val.slice(-4)}`;
}

export async function listApiKeys(): Promise<ApiKeyConfig[]> {
    const rows = await db.select().from(apiKeySlots).orderBy(apiKeySlots.name);
    const keys: ApiKeyConfig[] = [];

    for (const slot of rows) {
        const val = await resolveSecret(slot.envVar);
        keys.push({
            id: slot.id,
            name: slot.name,
            provider: slot.provider,
            envVar: slot.envVar,
            maskedValue: maskValue(val),
            configured: !!val && val.length > 0,
            testEndpoint: slot.testEndpoint ?? undefined,
            custom: slot.isCustom,
            authHeaderName: slot.authHeaderName ?? undefined,
        });
    }
    return keys;
}

export async function updateApiKey(id: string, value: string): Promise<boolean> {
    const rows = await db.select().from(apiKeySlots).where(eq(apiKeySlots.id, id)).limit(1);
    if (!rows[0]) return false;
    // Write to Redis (hot-reload)
    await setConfig(rows[0].envVar, value);
    // Also persist to Vault when available
    const vaultPath = `api-keys/${rows[0].envVar.toLowerCase().replace(/_/g, '-')}`;
    await secrets.set(vaultPath, value).catch(() => { /* Vault unavailable, Redis is still primary */ });
    return true;
}

export async function addCustomApiKey(def: { name: string; provider: string; envVar: string; testEndpoint?: string; authHeaderName?: string }, value?: string): Promise<ApiKeyConfig> {
    const id = `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const now = new Date();

    await db.insert(apiKeySlots).values({
        id,
        name: def.name,
        provider: def.provider,
        envVar: def.envVar,
        testEndpoint: def.testEndpoint ?? null,
        authHeaderName: def.authHeaderName ?? null,
        isCustom: true,
        createdAt: now,
        updatedAt: now,
    });

    if (value) await setConfig(def.envVar, value);
    log.info('Custom API key slot added', { id, name: def.name });

    const val = value || null;
    return {
        id, name: def.name, provider: def.provider, envVar: def.envVar,
        maskedValue: maskValue(val), configured: !!val, custom: true,
        testEndpoint: def.testEndpoint, authHeaderName: def.authHeaderName,
    };
}

export async function deleteCustomApiKey(id: string): Promise<boolean> {
    const rows = await db.select().from(apiKeySlots).where(eq(apiKeySlots.id, id)).limit(1);
    if (!rows[0] || !rows[0].isCustom) return false;
    await connection.del(`${PREFIX}${rows[0].envVar}`).catch(() => { });
    await db.delete(apiKeySlots).where(eq(apiKeySlots.id, id));
    log.info('Custom API key slot deleted', { id });
    return true;
}

export async function testApiKey(id: string): Promise<{ success: boolean; status?: number; message: string }> {
    const rows = await db.select().from(apiKeySlots).where(eq(apiKeySlots.id, id)).limit(1);
    const slot = rows[0];
    if (!slot) return { success: false, message: 'Unknown API key slot' };
    if (!slot.testEndpoint) return { success: false, message: 'No test endpoint configured for this provider' };

    const val = await resolveSecret(slot.envVar);
    if (!val) return { success: false, message: 'API key not configured' };

    try {
        const headers: Record<string, string> = { 'Accept': 'application/json' };

        // Query-param auth: authHeaderName starts with "?" (e.g. "?key" → appends ?key=VALUE)
        let targetUrl = slot.testEndpoint;
        let method = 'GET';
        let body: string | undefined;

        if (slot.authHeaderName && slot.authHeaderName.startsWith('?')) {
            // Strip leading "?" and any trailing "=" for the param name
            const paramName = slot.authHeaderName.slice(1).replace(/=$/, '');
            const urlObj = new URL(slot.testEndpoint);
            urlObj.searchParams.set(paramName, val);
            targetUrl = urlObj.toString();
        } else if (slot.authHeaderName === 'Auth-Key') {
            // Abuse.ch APIs (ThreatFox, MalwareBazaar, URLhaus) require POST with Auth-Key header
            method = 'POST';
            headers['Auth-Key'] = val;
            body = JSON.stringify({ query: 'get_iocs', days: 1 });
        } else if (slot.authHeaderName === 'x-api-key' && slot.testEndpoint.includes('api.exa.ai')) {
            // Exa Search API requires POST with JSON body
            method = 'POST';
            headers['Content-Type'] = 'application/json';
            headers['x-api-key'] = val;
            body = JSON.stringify({ query: 'test', numResults: 1 });
        } else if (slot.authHeaderName === 'API-KEY') {
            // ZoomEye API v2 requires POST for all endpoints
            method = 'POST';
            headers['API-KEY'] = val;
        } else if (slot.authHeaderName === 'Basic') {
            // HTTP Basic Auth (e.g. RiskIQ) — read companion _USER env var
            const userEnvKey = slot.envVar.replace(/_API_KEY$|_PASSWORD$/, '_USER');
            const user = await getConfig(userEnvKey);
            if (!user) return { success: false, message: `Missing companion env ${userEnvKey} for Basic auth` };
            const encoded = Buffer.from(`${user}:${val}`).toString('base64');
            headers['Authorization'] = `Basic ${encoded}`;
        } else if (slot.authHeaderName) {
            if (slot.authHeaderName === 'Bearer') {
                headers['Authorization'] = `Bearer ${val}`;
            } else {
                headers[slot.authHeaderName] = val;
            }
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const res = await fetch(targetUrl, { method, headers, body, signal: controller.signal });
        clearTimeout(timeout);

        return {
            success: res.ok,
            status: res.status,
            message: res.ok ? 'Connection successful' : `HTTP ${res.status}: ${res.statusText}`,
        };
    } catch (err) {
        const msg = (err as Error).name === 'AbortError' ? 'Connection timed out (10s)' : ((err as Error).message || 'Connection failed');
        return { success: false, message: msg };
    }
}

// ============================================================================
// Service Connections (PostgreSQL-backed)
// ============================================================================

export interface ServiceConfig {
    id: string;
    name: string;
    envVars: { key: string; label: string; secret?: boolean; placeholder?: string }[];
    custom?: boolean;
}

export async function listServices(): Promise<Array<ServiceConfig & { values: Record<string, string | null> }>> {
    const rows = await db.select().from(servicesConfig).orderBy(servicesConfig.name);
    const result = [];

    for (const svc of rows) {
        const envVars = (svc.envVars as { key: string; label: string; secret?: boolean; placeholder?: string }[]) || [];
        const values: Record<string, string | null> = {};
        for (const ev of envVars) {
            const val = await getConfig(ev.key);
            values[ev.key] = ev.secret ? maskValue(val) : val;
        }
        result.push({
            id: svc.id,
            name: svc.name,
            envVars,
            custom: svc.isCustom,
            values,
        });
    }
    return result;
}

export async function updateService(id: string, updates: Record<string, string>): Promise<boolean> {
    const rows = await db.select().from(servicesConfig).where(eq(servicesConfig.id, id)).limit(1);
    if (!rows[0]) return false;
    const envVars = (rows[0].envVars as { key: string; label: string; secret?: boolean }[]) || [];
    for (const [key, value] of Object.entries(updates)) {
        if (envVars.some(ev => ev.key === key)) {
            await setConfig(key, value);
        }
    }
    return true;
}

export async function addCustomService(def: { name: string; envVars: { key: string; label: string; secret?: boolean }[] }, values?: Record<string, string>): Promise<ServiceConfig & { values: Record<string, string | null> }> {
    const id = `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const now = new Date();

    await db.insert(servicesConfig).values({
        id,
        name: def.name,
        envVars: def.envVars,
        isCustom: true,
        createdAt: now,
        updatedAt: now,
    });

    if (values) {
        for (const [key, val] of Object.entries(values)) {
            await setConfig(key, val);
        }
    }

    log.info('Custom service added', { id, name: def.name });
    const resolvedValues: Record<string, string | null> = {};
    for (const ev of def.envVars) {
        const v = values?.[ev.key] || null;
        resolvedValues[ev.key] = ev.secret ? maskValue(v) : v;
    }
    return { id, name: def.name, envVars: def.envVars, custom: true, values: resolvedValues };
}

export async function deleteCustomService(id: string): Promise<boolean> {
    const rows = await db.select().from(servicesConfig).where(eq(servicesConfig.id, id)).limit(1);
    if (!rows[0] || !rows[0].isCustom) return false;
    const envVars = (rows[0].envVars as { key: string; label: string; secret?: boolean }[]) || [];
    for (const ev of envVars) {
        await connection.del(`${PREFIX}${ev.key}`).catch(() => { });
    }
    await db.delete(servicesConfig).where(eq(servicesConfig.id, id));
    log.info('Custom service deleted', { id });
    return true;
}

// ============================================================================
// Feed Sync History (Phase AC — MISP/IntelOwl inspired)
// ============================================================================

export interface FeedSyncRun {
    id: string;
    feedId: string;
    status: 'completed' | 'failed' | 'running';
    startedAt: string;
    completedAt: string | null;
    durationMs: number | null;
    itemsIngested: number;
    errors: number;
    errorDetails: string | null;
    triggeredBy: 'scheduler' | 'manual';
}

// `feed_sync_runs` is created by migration `0037_feed_sync_runs.sql`
// (was previously a runtime `CREATE TABLE IF NOT EXISTS` here that spammed
// Postgres NOTICEs on every boot).

/** Record a feed sync run */
export async function recordFeedSyncRun(feedId: string, stats: {
    status: 'completed' | 'failed';
    startedAt: Date;
    itemsIngested: number;
    errors: number;
    errorDetails?: string;
    triggeredBy?: 'scheduler' | 'manual';
}): Promise<void> {
    const durationMs = Date.now() - stats.startedAt.getTime();
    const esc = (s: string) => s.replace(/'/g, "''");
    const errDetail = stats.errorDetails ? `'${esc(stats.errorDetails)}'` : 'NULL';
    const trigger = stats.triggeredBy || 'scheduler';
    await rawQuery(sql.raw(`
        INSERT INTO feed_sync_runs (feed_id, status, started_at, completed_at, duration_ms, items_ingested, errors, error_details, triggered_by)
        VALUES ('${esc(feedId)}', '${stats.status}', '${stats.startedAt.toISOString()}', NOW(), ${durationMs}, ${stats.itemsIngested}, ${stats.errors}, ${errDetail}, '${trigger}')
    `));
    log.info('Feed sync run recorded', { feedId, status: stats.status, durationMs, items: stats.itemsIngested });
}

/** Get feed sync history */
export async function getFeedSyncHistory(feedId: string, limit: number = 20): Promise<FeedSyncRun[]> {
    const esc = (s: string) => s.replace(/'/g, "''");
    const result = await rawQuery<{
        id: string; feed_id: string; status: string; started_at: string;
        completed_at: string | null; duration_ms: number | null;
        items_ingested: number; errors: number; error_details: string | null;
        triggered_by: string;
    }>(sql.raw(`
        SELECT * FROM feed_sync_runs
        WHERE feed_id = '${esc(feedId)}'
        ORDER BY started_at DESC
        LIMIT ${limit}
    `));

    return (result.rows || []).map(r => ({
        id: r.id,
        feedId: r.feed_id,
        status: r.status as FeedSyncRun['status'],
        startedAt: r.started_at,
        completedAt: r.completed_at,
        durationMs: r.duration_ms,
        itemsIngested: r.items_ingested,
        errors: r.errors,
        errorDetails: r.error_details,
        triggeredBy: r.triggered_by as FeedSyncRun['triggeredBy'],
    }));
}

/** Test feed URL connectivity */
export async function testFeedConnectivity(feedId: string): Promise<{
    success: boolean; statusCode?: number; latencyMs: number; message: string;
}> {
    const feed = await getFeedById(feedId);
    if (!feed) return { success: false, latencyMs: 0, message: 'Feed not found' };
    if (!feed.url) return { success: false, latencyMs: 0, message: 'Feed has no URL configured' };

    // Resolve auth header if needed
    const headers: Record<string, string> = { 'Accept': '*/*', 'User-Agent': 'Rinjani-CTI/1.0' };
    if (feed.authHeader && feed.authKeyRef) {
        const val = await resolveSecret(feed.authKeyRef);
        if (val) headers[feed.authHeader] = val;
    }

    const start = performance.now();
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        const res = await fetch(feed.url, { method: 'HEAD', headers, signal: controller.signal }).catch(
            // HEAD may not be supported, retry with GET
            () => fetch(feed.url!, { method: 'GET', headers, signal: controller.signal })
        );
        clearTimeout(timeout);
        const latencyMs = Math.round(performance.now() - start);
        return {
            success: res.ok,
            statusCode: res.status,
            latencyMs,
            message: res.ok ? `Reachable (${res.status})` : `HTTP ${res.status}: ${res.statusText}`,
        };
    } catch (err) {
        const latencyMs = Math.round(performance.now() - start);
        const msg = (err as Error).name === 'AbortError' ? 'Connection timed out (15s)' : ((err as Error).message || 'Connection failed');
        return { success: false, latencyMs, message: msg };
    }
}
