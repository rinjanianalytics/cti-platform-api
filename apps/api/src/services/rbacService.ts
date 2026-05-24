/**
 * RBAC Service — Permission Resolution & Cache
 *
 * Provides in-memory cached permission resolution for roles and users.
 * Supports wildcard permissions (e.g., '*', 'iocs:*').
 * Also maintains a route policy registry for the API access matrix UI.
 *
 * Cache is invalidated automatically when roles/permissions change via admin API.
 */

import { db, eq } from '@rinjani/db';
import { roles as rolesTable } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('RBAC');

// ============================================================================
// Types
// ============================================================================

export interface RoutePolicyEntry {
    /** Route pattern (e.g., '/v1/iocs/*') */
    pattern: string;
    /** HTTP method or '*' for all */
    method: string;
    /** API group name for UI display */
    group: string;
    /** Required permissions (any one grants access) */
    requiredPermissions: string[];
    /** Required roles (legacy — any one grants access) */
    requiredRoles: string[];
}

export interface RbacAccessEntry {
    role: string;
    permission: string;
    granted: boolean;
    reason: 'wildcard' | 'exact' | 'prefix' | 'denied';
}

// ============================================================================
// Permission Cache
// ============================================================================

interface CachedRole {
    id: string;
    name: string;
    defaultPermissions: string[];
    fetchedAt: number;
}

const CACHE_TTL = 60_000; // 60 seconds
let roleCache: Map<string, CachedRole> = new Map();
let cacheTimestamp = 0;

async function loadRolesIntoCache(): Promise<void> {
    const now = Date.now();
    if (cacheTimestamp > 0 && now - cacheTimestamp < CACHE_TTL) return; // still valid

    try {
        const rows = await db.select().from(rolesTable);
        roleCache = new Map();
        for (const r of rows) {
            roleCache.set(r.id, {
                id: r.id,
                name: r.name,
                defaultPermissions: (r.defaultPermissions as string[]) || [],
                fetchedAt: now,
            });
        }
        cacheTimestamp = now;
        log.debug('RBAC cache refreshed', { roles: roleCache.size });
    } catch (err) {
        log.warn('Failed to refresh RBAC cache', { error: (err as Error).message });
    }
}

/** Invalidate the role permission cache (call after role/permission changes) */
export function invalidateRbacCache(): void {
    cacheTimestamp = 0;
    roleCache.clear();
    log.info('RBAC cache invalidated');
}

// ============================================================================
// Permission Resolution
// ============================================================================

/**
 * Resolve effective permissions for a user based on their role + overrides.
 *
 * @param role - Platform role ID (e.g., 'admin', 'analyst')
 * @param userPermissions - User-specific permission overrides
 * @returns Merged unique permission list
 */
export async function resolvePermissions(role: string, userPermissions: string[] = []): Promise<string[]> {
    await loadRolesIntoCache();

    const roleDef = roleCache.get(role);
    const rolePerms = roleDef?.defaultPermissions || [];

    // Merge: role defaults + user overrides, deduplicated
    return [...new Set([...rolePerms, ...userPermissions])];
}

/**
 * Check if a set of permissions satisfies a required permission.
 * Supports wildcards:
 *   '*'       → matches everything
 *   'iocs:*'  → matches 'iocs:read', 'iocs:write', etc.
 *   'iocs:read' → exact match only
 */
export function hasPermission(grantedPermissions: string[], required: string): boolean {
    for (const perm of grantedPermissions) {
        // Full wildcard
        if (perm === '*') return true;

        // Exact match
        if (perm === required) return true;

        // Prefix wildcard (e.g., 'iocs:*' matches 'iocs:read')
        if (perm.endsWith(':*')) {
            const prefix = perm.slice(0, -1); // 'iocs:'
            if (required.startsWith(prefix)) return true;
        }
    }
    return false;
}

/**
 * Check if any of the required permissions are satisfied.
 * (OR logic — user needs at least one of the required permissions)
 */
export function hasAnyPermission(grantedPermissions: string[], required: string[]): boolean {
    return required.some(req => hasPermission(grantedPermissions, req));
}

// ============================================================================
// Route Policy Registry
// ============================================================================

/**
 * Built-in route policies mapping API routes to required permissions/roles.
 * This is the source of truth for the API Access Matrix UI.
 */
const ROUTE_POLICIES: RoutePolicyEntry[] = [
    // ── Threat Intelligence (Read) ──
    { pattern: '/v1/iocs', method: 'GET', group: 'Threat Intel', requiredPermissions: ['iocs:read'], requiredRoles: [] },
    { pattern: '/v1/iocs/:id', method: 'GET', group: 'Threat Intel', requiredPermissions: ['iocs:read'], requiredRoles: [] },
    { pattern: '/v1/search/*', method: 'GET', group: 'Threat Intel', requiredPermissions: ['search:execute'], requiredRoles: [] },
    { pattern: '/v1/stats', method: 'GET', group: 'Threat Intel', requiredPermissions: ['iocs:read'], requiredRoles: [] },
    { pattern: '/v1/graph/*', method: 'GET', group: 'Threat Intel', requiredPermissions: ['iocs:read'], requiredRoles: [] },

    // ── Threat Intelligence (Write) ──
    { pattern: '/v1/iocs', method: 'POST', group: 'Threat Intel (Write)', requiredPermissions: ['iocs:write'], requiredRoles: [] },
    { pattern: '/v1/iocs/:id', method: 'PUT', group: 'Threat Intel (Write)', requiredPermissions: ['iocs:write'], requiredRoles: [] },
    { pattern: '/v1/iocs/:id', method: 'DELETE', group: 'Threat Intel (Write)', requiredPermissions: ['iocs:write'], requiredRoles: [] },
    { pattern: '/v1/batch/*', method: 'POST', group: 'Threat Intel (Write)', requiredPermissions: ['iocs:write'], requiredRoles: [] },
    { pattern: '/v1/bulk/import/*', method: 'POST', group: 'Threat Intel (Write)', requiredPermissions: ['iocs:write'], requiredRoles: [] },
    { pattern: '/v1/bulk/export/*', method: 'GET', group: 'Threat Intel (Write)', requiredPermissions: ['export:execute'], requiredRoles: [] },

    // ── Enrichment ──
    { pattern: '/v1/enrich/*', method: '*', group: 'Enrichment', requiredPermissions: ['enrichment:execute'], requiredRoles: [] },

    // ── Feed Management ──
    { pattern: '/v1/feeds', method: 'GET', group: 'Feeds', requiredPermissions: ['feeds:read'], requiredRoles: [] },
    { pattern: '/v1/feeds/*', method: 'PUT', group: 'Feeds', requiredPermissions: ['feeds:write'], requiredRoles: [] },
    { pattern: '/v1/feeds/*/sync', method: 'POST', group: 'Feeds', requiredPermissions: ['feeds:trigger'], requiredRoles: [] },

    // ── Alerts ──
    { pattern: '/v1/alerts', method: 'GET', group: 'Alerts', requiredPermissions: ['alerts:read'], requiredRoles: [] },
    { pattern: '/v1/alerts/*', method: 'POST', group: 'Alerts', requiredPermissions: ['alerts:read'], requiredRoles: [] },

    // ── Reports ──
    { pattern: '/v1/reports/*', method: 'GET', group: 'Reports', requiredPermissions: ['reports:read'], requiredRoles: [] },

    // ── Webhooks ──
    { pattern: '/v1/webhooks', method: 'GET', group: 'Webhooks', requiredPermissions: ['webhooks:read'], requiredRoles: [] },
    { pattern: '/v1/webhooks', method: 'POST', group: 'Webhooks', requiredPermissions: ['webhooks:write'], requiredRoles: [] },
    { pattern: '/v1/webhooks/:id', method: 'DELETE', group: 'Webhooks', requiredPermissions: ['webhooks:write'], requiredRoles: [] },

    // ── API Keys ──
    { pattern: '/admin/config/api-keys', method: 'GET', group: 'API Keys', requiredPermissions: ['api-keys:read'], requiredRoles: [] },
    { pattern: '/admin/config/api-keys/*', method: 'PUT', group: 'API Keys', requiredPermissions: ['api-keys:generate'], requiredRoles: [] },

    // ── User Management ──
    { pattern: '/admin/users/*', method: '*', group: 'User Management', requiredPermissions: ['users:write'], requiredRoles: ['admin'] },

    // ── System Administration ──
    { pattern: '/admin/queues/*', method: '*', group: 'System Admin', requiredPermissions: ['system:write'], requiredRoles: ['admin'] },
    { pattern: '/admin/jobs/*', method: 'POST', group: 'System Admin', requiredPermissions: ['system:write'], requiredRoles: ['admin', 'analyst'] },
    { pattern: '/admin/config/*', method: 'PUT', group: 'System Admin', requiredPermissions: ['system:write'], requiredRoles: ['admin'] },

    // ── Audit ──
    { pattern: '/v1/audit/*', method: 'GET', group: 'Audit', requiredPermissions: ['audit:read'], requiredRoles: [] },

    // ── STIX / TAXII ──
    { pattern: '/v1/stix/*', method: '*', group: 'STIX/TAXII', requiredPermissions: ['iocs:write'], requiredRoles: [] },
    { pattern: '/taxii2/*', method: '*', group: 'STIX/TAXII', requiredPermissions: ['iocs:read'], requiredRoles: [] },

    // ── YARA ──
    { pattern: '/v1/yara/rules', method: 'GET', group: 'YARA', requiredPermissions: ['iocs:read'], requiredRoles: [] },
    { pattern: '/v1/yara/rules', method: 'POST', group: 'YARA', requiredPermissions: ['system:write'], requiredRoles: ['admin'] },
];

/** Get all route policies (for the UI access matrix) */
export function getRoutePolicies(): RoutePolicyEntry[] {
    return [...ROUTE_POLICIES];
}

/** Get the unique permission groups for the matrix view */
export function getRouteGroups(): string[] {
    return [...new Set(ROUTE_POLICIES.map(p => p.group))];
}

/**
 * Build the full access matrix: for each role, which groups are accessible.
 */
export async function buildAccessMatrix(): Promise<{
    roles: Array<{ id: string; name: string }>;
    groups: string[];
    matrix: Record<string, Record<string, boolean>>;
}> {
    await loadRolesIntoCache();

    const roles = [...roleCache.values()].map(r => ({ id: r.id, name: r.name }));
    const groups = getRouteGroups();

    // For each role, check each group
    const matrix: Record<string, Record<string, boolean>> = {};

    for (const role of roles) {
        matrix[role.id] = {};
        const perms = role.id === 'admin'
            ? ['*']
            : (roleCache.get(role.id)?.defaultPermissions || []);

        for (const group of groups) {
            // A role has access to a group if it can satisfy ANY route in that group
            const groupPolicies = ROUTE_POLICIES.filter(p => p.group === group);
            const hasAccess = groupPolicies.some(policy => {
                // Check permission-based access
                if (policy.requiredPermissions.length > 0) {
                    if (hasAnyPermission(perms, policy.requiredPermissions)) return true;
                }
                // Check legacy role-based access
                if (policy.requiredRoles.length > 0) {
                    if (policy.requiredRoles.includes(role.id)) return true;
                }
                // No requirements = open access
                if (policy.requiredPermissions.length === 0 && policy.requiredRoles.length === 0) {
                    return true;
                }
                return false;
            });
            matrix[role.id][group] = hasAccess;
        }
    }

    return { roles, groups, matrix };
}

// ============================================================================
// Keycloak Role Mapping
// ============================================================================

/**
 * Default mapping: Keycloak realm role → Rinjani platform role.
 * Stored in memory; can be overridden via admin API (persisted to Redis).
 */
let keycloakRoleMapping: Record<string, string> = {
    'realm-admin': 'admin',
    'admin': 'admin',
    'analyst': 'analyst',
    'developer': 'developer',
    'auditor': 'auditor',
    'viewer': 'viewer',
    'uma_authorization': 'viewer',  // default Keycloak role
};

/** Get current Keycloak → platform role mapping */
export function getKeycloakMapping(): Record<string, string> {
    return { ...keycloakRoleMapping };
}

/** Update the mapping (called from admin API) */
export function setKeycloakMapping(mapping: Record<string, string>): void {
    keycloakRoleMapping = { ...mapping };
    log.info('Keycloak role mapping updated', { mappings: Object.keys(mapping).length });
}

/**
 * Map an array of Keycloak roles to the best platform role.
 * Priority: admin > analyst > developer > auditor > viewer
 */
export function mapKeycloakRolesToPlatformRole(kcRoles: string[]): string {
    const priority = ['admin', 'analyst', 'developer', 'auditor', 'viewer'];

    const platformRoles = kcRoles
        .map(kcRole => keycloakRoleMapping[kcRole])
        .filter(Boolean) as string[];

    // Return the highest-priority role
    for (const role of priority) {
        if (platformRoles.includes(role)) return role;
    }

    return 'viewer'; // Fallback
}

// ============================================================================
// Persistence helpers (Redis-backed mapping storage)
// ============================================================================

const MAPPING_REDIS_KEY = 'rbac:keycloak-mapping';

/** Load Keycloak mapping from Redis (called at startup) */
export async function loadKeycloakMappingFromRedis(): Promise<void> {
    try {
        const { getConfig } = await import('./configStore');
        const stored = await getConfig(MAPPING_REDIS_KEY);
        if (stored) {
            keycloakRoleMapping = JSON.parse(stored) as Record<string, string>;
            log.info('Loaded Keycloak mapping from Redis', { mappings: Object.keys(keycloakRoleMapping).length });
        }
    } catch {
        // Redis unavailable or no stored mapping — use defaults
    }
}

/** Save Keycloak mapping to Redis */
export async function saveKeycloakMappingToRedis(): Promise<void> {
    try {
        const { setConfig } = await import('./configStore');
        await setConfig(MAPPING_REDIS_KEY, JSON.stringify(keycloakRoleMapping));
    } catch {
        log.warn('Failed to persist Keycloak mapping to Redis');
    }
}
