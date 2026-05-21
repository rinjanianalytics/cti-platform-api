/**
 * User Service — DB-backed User CRUD with Role & Permission CRUD
 *
 * Provides user management operations against the PostgreSQL users table.
 * Roles and permission modules are fetched from the database (seeded via seed.ts).
 * API tokens are auto-generated using crypto.randomBytes (OpenSSL-backed).
 *
 * Roles align with the Rinjani RBAC Design System:
 *   admin | analyst | developer | auditor | viewer  (plus custom roles)
 */

import { and, db, desc, eq, ilike, sql } from '@rinjani/db';
import { users, roles as rolesTable, permissionModules as permModulesTable } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from 'crypto';

const log = createLogger('UserService');

// ============================================================================
// Password Hashing (crypto.scrypt — no external deps)
// ============================================================================

/** Hash a plaintext password with a random 16-byte salt */
export function hashPassword(password: string): string {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

/** Verify a plaintext password against a stored hash */
export function verifyPassword(password: string, stored: string): boolean {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) return false;
    const derivedKey = scryptSync(password, salt, 64);
    const storedKey = Buffer.from(hash, 'hex');
    return timingSafeEqual(derivedKey, storedKey);
}

/** Change a user's password (verifies current password first) */
export async function changePassword(userId: string, currentPassword: string, newPassword: string): Promise<{ success: boolean; error?: string }> {
    const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!rows[0]) return { success: false, error: 'User not found' };

    const user = rows[0];

    // If user has a password hash, verify current password
    if (user.passwordHash) {
        if (!verifyPassword(currentPassword, user.passwordHash)) {
            return { success: false, error: 'Current password is incorrect' };
        }
    }

    // Hash and store new password
    const newHash = hashPassword(newPassword);
    await db.update(users).set({ passwordHash: newHash, updatedAt: new Date() }).where(eq(users.id, userId));
    log.info('Password changed', { userId });
    return { success: true };
}

// ============================================================================
// Types
// ============================================================================

export type UserRole = string; // Dynamic — fetched from DB

export interface UserRecord {
    id: string;
    email: string;
    name: string;
    avatarUrl: string | null;
    roles: string[];
    permissions: string[];
    isActive: boolean;
    lastLogin: string | null;
    apiToken: string | null;
    createdAt: string;
    updatedAt: string;
}

export interface CreateUserInput {
    email: string;
    name: string;
    role: string;
    permissions?: string[];
}

export interface UpdateUserInput {
    email?: string;
    name?: string;
    role?: string;
    permissions?: string[];
    isActive?: boolean;
    avatarUrl?: string | null;
}

export interface UserListFilters {
    role?: string;
    status?: 'active' | 'inactive' | 'all';
    search?: string;
    page?: number;
    limit?: number;
}

// ============================================================================
// Role & Permission Module Types (from DB)
// ============================================================================

export interface RoleDefinition {
    id: string;
    name: string;
    description: string;
    defaultPermissions: string[];
    isSystem: boolean;
    createdAt: string;
    updatedAt: string;
}

export interface PermissionDef {
    id: string;
    name: string;
    description: string;
}

export interface PermissionModule {
    id: string;
    name: string;
    icon: string;
    permissions: PermissionDef[];
    isSystem: boolean;
    createdAt: string;
    updatedAt: string;
}

// ============================================================================
// API Token Generation (OpenSSL-backed via Node crypto)
// ============================================================================

/** Generate a secure API token: rjn_<32 random hex chars> (16 bytes entropy) */
export function generateApiToken(): string {
    return `rjn_${randomBytes(16).toString('hex')}`;
}

// ============================================================================
// Bootstrap — ensure built-in roles and permission modules exist
// ============================================================================

const BUILTIN_ROLES = [
    {
        id: 'admin',
        name: 'Administrator',
        description: 'Full system access — manage users, settings, feeds, and all platform operations.',
        defaultPermissions: ['*'],
        isSystem: true,
    },
    {
        id: 'analyst',
        name: 'Security Analyst',
        description: 'View and edit threat data, run enrichments, access strategic reports.',
        defaultPermissions: [
            'iocs:read', 'iocs:write', 'feeds:read', 'enrichment:execute',
            'reports:read', 'search:execute', 'export:execute', 'alerts:read',
        ],
        isSystem: true,
    },
    {
        id: 'developer',
        name: 'Developer',
        description: 'API access, webhook management, and integration development.',
        defaultPermissions: [
            'iocs:read', 'feeds:read', 'api-keys:read', 'api-keys:generate',
            'webhooks:read', 'webhooks:write', 'search:execute',
        ],
        isSystem: true,
    },
    {
        id: 'auditor',
        name: 'Auditor',
        description: 'Read-only access to audit logs, system activity, and compliance data.',
        defaultPermissions: [
            'audit:read', 'iocs:read', 'feeds:read', 'reports:read',
            'system:read', 'users:read',
        ],
        isSystem: true,
    },
    {
        id: 'viewer',
        name: 'Viewer',
        description: 'Read-only access to dashboards and threat intelligence.',
        defaultPermissions: [
            'iocs:read', 'feeds:read', 'reports:read', 'search:execute',
        ],
        isSystem: true,
    },
];

/**
 * Ensure all built-in system roles exist in the database.
 * Called at startup so the roles dropdown is never incomplete
 * (even if seed.ts was skipped or ran partially).
 */
export async function ensureBuiltInRoles(): Promise<void> {
    const now = new Date();
    for (const role of BUILTIN_ROLES) {
        await db.insert(rolesTable).values({
            ...role,
            createdAt: now,
            updatedAt: now,
        }).onConflictDoNothing();
    }
    log.info(`Ensured ${BUILTIN_ROLES.length} built-in roles exist`);
}

// ============================================================================
// Helpers
// ============================================================================

function toUserRecord(row: typeof users.$inferSelect): UserRecord {
    return {
        id: row.id,
        email: row.email,
        name: row.name,
        avatarUrl: row.avatarUrl ?? null,
        roles: (row.roles as string[]) || [],
        permissions: (row.permissions as string[]) || [],
        isActive: row.isActive,
        lastLogin: row.lastLogin?.toISOString() ?? null,
        apiToken: row.apiToken ?? null,
        createdAt: row.createdAt.toISOString(),
        updatedAt: row.updatedAt.toISOString(),
    };
}

// ============================================================================
// User CRUD Operations
// ============================================================================

export async function listUsers(filters: UserListFilters = {}): Promise<{ users: UserRecord[]; total: number; page: number; limit: number }> {
    const page = Math.max(1, filters.page || 1);
    const limit = Math.min(100, Math.max(1, filters.limit || 50));
    const offset = (page - 1) * limit;

    const conditions = [];

    if (filters.status === 'active') {
        conditions.push(eq(users.isActive, true));
    } else if (filters.status === 'inactive') {
        conditions.push(eq(users.isActive, false));
    }

    if (filters.search) {
        const term = `%${filters.search}%`;
        conditions.push(
            sql`(${users.email} ILIKE ${term} OR ${users.name} ILIKE ${term})`
        );
    }

    if (filters.role && filters.role !== 'all') {
        conditions.push(
            sql`${users.roles}::jsonb @> ${JSON.stringify([filters.role])}::jsonb`
        );
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const [rows, countResult] = await Promise.all([
        db.select().from(users).where(whereClause).orderBy(desc(users.createdAt)).limit(limit).offset(offset),
        db.select({ count: sql<number>`count(*)::int` }).from(users).where(whereClause),
    ]);

    return {
        users: rows.map(toUserRecord),
        total: countResult[0]?.count ?? 0,
        page,
        limit,
    };
}

export async function getUserById(id: string): Promise<UserRecord | null> {
    const rows = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return rows[0] ? toUserRecord(rows[0]) : null;
}

export async function getUserByEmail(email: string): Promise<UserRecord | null> {
    const rows = await db.select().from(users).where(eq(users.email, email)).limit(1);
    return rows[0] ? toUserRecord(rows[0]) : null;
}

export async function createUser(input: CreateUserInput): Promise<UserRecord> {
    // Check for duplicate email
    const existing = await getUserByEmail(input.email);
    if (existing) {
        throw new Error(`Email already exists: ${input.email}`);
    }

    const now = new Date();
    const id = randomUUID();
    const apiToken = generateApiToken();

    // Look up the role to get default permissions
    const roleDef = await getRoleById(input.role);
    const defaultPerms = roleDef?.defaultPermissions || [];

    const [row] = await db.insert(users).values({
        id,
        email: input.email,
        name: input.name,
        roles: [input.role],
        permissions: input.permissions || defaultPerms,
        isActive: true,
        apiToken,
        createdAt: now,
        updatedAt: now,
    }).returning();

    log.info('User created', { id: row.id, email: row.email, role: input.role, tokenGenerated: true });
    return toUserRecord(row);
}

export async function updateUser(id: string, input: UpdateUserInput): Promise<UserRecord | null> {
    const existing = await getUserById(id);
    if (!existing) return null;

    const updates: Record<string, unknown> = { updatedAt: new Date() };

    if (input.email !== undefined) updates.email = input.email;
    if (input.name !== undefined) updates.name = input.name;
    if (input.role !== undefined) updates.roles = [input.role];
    if (input.permissions !== undefined) updates.permissions = input.permissions;
    if (input.isActive !== undefined) updates.isActive = input.isActive;
    if (input.avatarUrl !== undefined) updates.avatarUrl = input.avatarUrl;

    const [row] = await db.update(users).set(updates).where(eq(users.id, id)).returning();
    log.info('User updated', { id, updates: Object.keys(updates).filter(k => k !== 'updatedAt') });
    return toUserRecord(row);
}

export async function deleteUser(id: string): Promise<boolean> {
    // Soft-delete: set isActive = false
    const [row] = await db.update(users).set({ isActive: false, updatedAt: new Date() }).where(eq(users.id, id)).returning();
    if (!row) return false;
    log.info('User deactivated (soft delete)', { id });
    return true;
}

/**
 * Hard-delete (purge) a user. Used for permanent bans / GDPR right-to-erasure /
 * test-account cleanup. UNLIKE `deleteUser`, this actually removes the row.
 *
 * FK landscape:
 *   - userOrganizations / apiKeys / sessions / oauthIdentities — cascade (drop)
 *   - playbooks.createdBy / sightings.createdBy — no cascade (would block).
 *     We NULL them out first to preserve the historic record while severing
 *     the identity link.
 *   - audit_logs.userId — no FK constraint, history preserved as-is (the
 *     audit trail intentionally outlives the user).
 *
 * Returns true on success, false if the user didn't exist.
 */
export async function purgeUser(id: string): Promise<boolean> {
    // Lazy-import sibling schemas to avoid circular deps.
    const { playbooks } = await import('@rinjani/db/schema');
    const { sightings } = await import('@rinjani/db/schema');

    // Null out FK refs first so the user delete isn't blocked.
    await db.update(playbooks).set({ createdBy: null }).where(eq(playbooks.createdBy, id));
    await db.update(sightings).set({ createdBy: null }).where(eq(sightings.createdBy, id));

    const [row] = await db.delete(users).where(eq(users.id, id)).returning({ id: users.id });
    if (!row) return false;
    log.warn('User PURGED (hard delete) — row removed', { id });
    return true;
}

export async function activateUser(id: string): Promise<UserRecord | null> {
    const [row] = await db.update(users).set({ isActive: true, updatedAt: new Date() }).where(eq(users.id, id)).returning();
    if (!row) return null;
    log.info('User activated', { id });
    return toUserRecord(row);
}

export async function deactivateUser(id: string): Promise<UserRecord | null> {
    const [row] = await db.update(users).set({ isActive: false, updatedAt: new Date() }).where(eq(users.id, id)).returning();
    if (!row) return null;
    log.info('User deactivated', { id });
    return toUserRecord(row);
}

/** Regenerate a user's API token */
export async function regenerateApiToken(id: string): Promise<{ token: string } | null> {
    const newToken = generateApiToken();
    const [row] = await db.update(users).set({ apiToken: newToken, updatedAt: new Date() }).where(eq(users.id, id)).returning();
    if (!row) return null;
    log.info('API token regenerated', { id });
    return { token: newToken };
}

// ============================================================================
// Role CRUD (DB-backed, replaces hardcoded ROLE_DEFINITIONS)
// ============================================================================

export async function listRoles(): Promise<RoleDefinition[]> {
    const rows = await db.select().from(rolesTable).orderBy(rolesTable.name);
    return rows.map(r => ({
        id: r.id,
        name: r.name,
        description: r.description,
        defaultPermissions: (r.defaultPermissions as string[]) || [],
        isSystem: r.isSystem,
        createdAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
    }));
}

export async function getRoleById(id: string): Promise<RoleDefinition | null> {
    const rows = await db.select().from(rolesTable).where(eq(rolesTable.id, id)).limit(1);
    if (!rows[0]) return null;
    const r = rows[0];
    return {
        id: r.id,
        name: r.name,
        description: r.description,
        defaultPermissions: (r.defaultPermissions as string[]) || [],
        isSystem: r.isSystem,
        createdAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
    };
}

export async function createRole(input: { id: string; name: string; description: string; defaultPermissions: string[] }): Promise<RoleDefinition> {
    // Check duplicate
    const existing = await getRoleById(input.id);
    if (existing) throw new Error(`Role already exists: ${input.id}`);

    const now = new Date();
    const [row] = await db.insert(rolesTable).values({
        id: input.id,
        name: input.name,
        description: input.description,
        defaultPermissions: input.defaultPermissions,
        isSystem: false,
        createdAt: now,
        updatedAt: now,
    }).returning();

    log.info('Role created', { id: row.id, name: row.name });
    return {
        id: row.id,
        name: row.name,
        description: row.description,
        defaultPermissions: (row.defaultPermissions as string[]) || [],
        isSystem: row.isSystem,
        createdAt: row.createdAt.toISOString(),
        updatedAt: row.updatedAt.toISOString(),
    };
}

export async function updateRole(id: string, input: { name?: string; description?: string; defaultPermissions?: string[] }): Promise<RoleDefinition | null> {
    const existing = await getRoleById(id);
    if (!existing) return null;

    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (input.name !== undefined) updates.name = input.name;
    if (input.description !== undefined) updates.description = input.description;
    if (input.defaultPermissions !== undefined) updates.defaultPermissions = input.defaultPermissions;

    const [row] = await db.update(rolesTable).set(updates).where(eq(rolesTable.id, id)).returning();
    log.info('Role updated', { id });
    return {
        id: row.id,
        name: row.name,
        description: row.description,
        defaultPermissions: (row.defaultPermissions as string[]) || [],
        isSystem: row.isSystem,
        createdAt: row.createdAt.toISOString(),
        updatedAt: row.updatedAt.toISOString(),
    };
}

export async function deleteRole(id: string): Promise<boolean> {
    const existing = await getRoleById(id);
    if (!existing) return false;
    if (existing.isSystem) throw new Error('Cannot delete system role');

    await db.delete(rolesTable).where(eq(rolesTable.id, id));
    log.info('Role deleted', { id });
    return true;
}

// ============================================================================
// Permission Module CRUD (DB-backed, replaces hardcoded PERMISSION_MODULES)
// ============================================================================

export async function listPermissionModules(): Promise<PermissionModule[]> {
    const rows = await db.select().from(permModulesTable).orderBy(permModulesTable.name);
    return rows.map(m => ({
        id: m.id,
        name: m.name,
        icon: m.icon,
        permissions: (m.permissions as PermissionDef[]) || [],
        isSystem: m.isSystem,
        createdAt: m.createdAt.toISOString(),
        updatedAt: m.updatedAt.toISOString(),
    }));
}

export async function getPermissionModuleById(id: string): Promise<PermissionModule | null> {
    const rows = await db.select().from(permModulesTable).where(eq(permModulesTable.id, id)).limit(1);
    if (!rows[0]) return null;
    const m = rows[0];
    return {
        id: m.id,
        name: m.name,
        icon: m.icon,
        permissions: (m.permissions as PermissionDef[]) || [],
        isSystem: m.isSystem,
        createdAt: m.createdAt.toISOString(),
        updatedAt: m.updatedAt.toISOString(),
    };
}

export async function createPermissionModule(input: { id: string; name: string; icon: string; permissions: PermissionDef[] }): Promise<PermissionModule> {
    const existing = await getPermissionModuleById(input.id);
    if (existing) throw new Error(`Permission module already exists: ${input.id}`);

    const now = new Date();
    const [row] = await db.insert(permModulesTable).values({
        id: input.id,
        name: input.name,
        icon: input.icon,
        permissions: input.permissions,
        isSystem: false,
        createdAt: now,
        updatedAt: now,
    }).returning();

    log.info('Permission module created', { id: row.id });
    return {
        id: row.id,
        name: row.name,
        icon: row.icon,
        permissions: (row.permissions as PermissionDef[]) || [],
        isSystem: row.isSystem,
        createdAt: row.createdAt.toISOString(),
        updatedAt: row.updatedAt.toISOString(),
    };
}

export async function updatePermissionModule(id: string, input: { name?: string; icon?: string; permissions?: PermissionDef[] }): Promise<PermissionModule | null> {
    const existing = await getPermissionModuleById(id);
    if (!existing) return null;

    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (input.name !== undefined) updates.name = input.name;
    if (input.icon !== undefined) updates.icon = input.icon;
    if (input.permissions !== undefined) updates.permissions = input.permissions;

    const [row] = await db.update(permModulesTable).set(updates).where(eq(permModulesTable.id, id)).returning();
    log.info('Permission module updated', { id });
    return {
        id: row.id,
        name: row.name,
        icon: row.icon,
        permissions: (row.permissions as PermissionDef[]) || [],
        isSystem: row.isSystem,
        createdAt: row.createdAt.toISOString(),
        updatedAt: row.updatedAt.toISOString(),
    };
}

export async function deletePermissionModule(id: string): Promise<boolean> {
    const existing = await getPermissionModuleById(id);
    if (!existing) return false;
    if (existing.isSystem) throw new Error('Cannot delete system permission module');

    await db.delete(permModulesTable).where(eq(permModulesTable.id, id));
    log.info('Permission module deleted', { id });
    return true;
}
