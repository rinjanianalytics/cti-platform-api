/**
 * Authentication Middleware
 * 
 * Provides API key and JWT authentication for V3 API.
 * Supports multiple authentication methods:
 * - Bearer token (JWT)
 * - X-API-Key header
 * - Query parameter ?api_key=xxx
 */

import type { Context, Next } from 'hono';
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { createHmac } from 'crypto';

// ============================================================================
// Configuration
// ============================================================================

// Parse API_KEYS from environment: format "key1:role,key2:role"
function parseApiKeys(): Map<string, { name: string; role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer' }> {
    const keys = new Map<string, { name: string; role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer' }>();

    const envKeys = process.env.API_KEYS;
    if (envKeys) {
        envKeys.split(',').forEach((entry, index) => {
            const [key, role] = entry.trim().split(':');
            if (key && role && ['admin', 'analyst', 'developer', 'auditor', 'viewer'].includes(role)) {
                keys.set(key, {
                    name: `API Key ${index + 1}`,
                    role: role as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer'
                });
            }
        });
    }

    return keys;
}

const API_KEYS = parseApiKeys();

// JWT_SECRET is REQUIRED — no hardcoded fallback in production
const JWT_SECRET = process.env.JWT_SECRET || '';

/**
 * Validate that all required auth configuration is present.
 * Call this before the server starts listening.
 * Throws if critical auth config is missing.
 */
export function validateAuthConfig(): void {
    if (!process.env.JWT_SECRET) {
        throw new Error(
            '[Auth] FATAL: JWT_SECRET environment variable is not set. '
            + 'This is required for production. Set it in .env or via your secrets manager.'
        );
    }
    if (API_KEYS.size === 0 && !process.env.KEYCLOAK_URL) {
        console.warn(
            '[Auth] WARNING: No API_KEYS configured and Keycloak is unavailable. '
            + 'All requests will be unauthenticated unless using Keycloak OIDC.'
        );
    }
}

// ============================================================================
// Types
// ============================================================================

export interface AuthUser {
    id: string;
    name: string;
    role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
    permissions: string[];
    method: 'api_key' | 'jwt' | 'keycloak';
    tenantId?: string;
    tenantRole?: string;
}

declare module 'hono' {
    interface ContextVariableMap {
        user: AuthUser;
    }
}

// ============================================================================
// JWT Helpers
// ============================================================================

interface JWTPayload {
    sub: string;
    name: string;
    role: 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
    iat: number;
    exp: number;
    tenantId?: string;
    tenantRole?: string;
}

export function createJWT(payload: Omit<JWTPayload, 'iat'>): string {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);

    const fullPayload: JWTPayload = { ...payload, iat: now };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');

    const signature = createHmac('sha256', JWT_SECRET)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64url');

    return `${headerB64}.${payloadB64}.${signature}`;
}

export function verifyJWT(token: string): JWTPayload | null {
    try {
        const [headerB64, payloadB64, signature] = token.split('.');
        if (!headerB64 || !payloadB64 || !signature) return null;

        const expectedSignature = createHmac('sha256', JWT_SECRET)
            .update(`${headerB64}.${payloadB64}`)
            .digest('base64url');

        if (signature !== expectedSignature) return null;

        const payload: JWTPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return null;

        return payload;
    } catch {
        return null;
    }
}

// ============================================================================
// Authentication Middleware
// ============================================================================

export async function optionalAuth(c: Context, next: Next) {
    const authHeader = c.req.header('Authorization');
    const apiKey = c.req.header('X-API-Key') || c.req.query('api_key');

    if (apiKey && API_KEYS.has(apiKey)) {
        const keyInfo = API_KEYS.get(apiKey)!;
        c.set('user', {
            id: `key:${apiKey.substring(0, 8)}`,
            name: keyInfo.name,
            role: keyInfo.role,
            permissions: [],
            method: 'api_key',
        });
    } else if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.slice(7);
        const payload = verifyJWT(token);
        if (payload) {
            c.set('user', {
                id: payload.sub,
                name: payload.name,
                role: payload.role,
                permissions: [],
                method: 'jwt',
                tenantId: payload.tenantId,
                tenantRole: payload.tenantRole,
            });
        } else {
            // Fallback: try Keycloak-issued JWT
            try {
                const { keycloak } = await import('../services/keycloak');
                const { mapKeycloakRolesToPlatformRole } = await import('../services/rbacService');
                if (await keycloak.isAvailable()) {
                    const kcPayload = keycloak.decodeToken(token);
                    if (kcPayload && kcPayload.exp > Math.floor(Date.now() / 1000)) {
                        const kcRoles = keycloak.extractRoles(kcPayload);
                        const platformRole = mapKeycloakRolesToPlatformRole(kcRoles) as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
                        c.set('user', {
                            id: kcPayload.sub,
                            name: kcPayload.preferred_username || kcPayload.email || 'SSO User',
                            role: platformRole,
                            permissions: [],
                            method: 'keycloak' as const,
                        });
                    }
                }
            } catch {
                // Keycloak unavailable — token stays unverified
            }
        }
    }

    // Cookie fallback — dashboard mirrors the localStorage JWT into a
    // `rinjani_token` cookie on its own origin so embedded same-origin UIs
    // (e.g. Workbench at /admin/workbench, proxied through the dashboard's
    // Next.js rewrite) can ride our session without their own auth layer.
    // Only consulted if the Authorization header / API key didn't match.
    if (!c.get('user')) {
        const cookieHeader = c.req.header('Cookie');
        if (cookieHeader) {
            const m = cookieHeader.match(/(?:^|;\s*)rinjani_token=([^;]+)/);
            if (m) {
                const payload = verifyJWT(decodeURIComponent(m[1]));
                if (payload) {
                    c.set('user', {
                        id: payload.sub,
                        name: payload.name,
                        role: payload.role,
                        permissions: [],
                        method: 'jwt',
                        tenantId: payload.tenantId,
                        tenantRole: payload.tenantRole,
                    });
                }
            }
        }
    }

    // Eagerly resolve permissions from DB if user is authenticated
    const user = c.get('user');
    if (user && user.permissions.length === 0) {
        try {
            const { resolvePermissions } = await import('../services/rbacService');
            user.permissions = await resolvePermissions(user.role);
            c.set('user', user);
        } catch {
            // RBAC service unavailable — use empty permissions (role checks still work)
        }
    }

    await next();
}

export async function requireAuth(c: Context, next: Next) {
    await optionalAuth(c, async () => { });

    if (!c.get('user')) {
        throw new HTTPException(401, {
            message: 'Authentication required. Provide X-API-Key header or Bearer token.',
        });
    }

    await next();
}

export function requireRole(...roles: ('admin' | 'analyst' | 'developer' | 'auditor' | 'viewer')[]) {
    return async (c: Context, next: Next) => {
        const user = c.get('user');
        if (!user) throw new HTTPException(401, { message: 'Authentication required' });
        if (!roles.includes(user.role)) {
            throw new HTTPException(403, { message: `Access denied. Required role: ${roles.join(' or ')}` });
        }
        await next();
    };
}

/**
 * Permission-based access control middleware.
 * Checks if the authenticated user has any of the required permissions.
 * Supports wildcard permissions ('*', 'iocs:*').
 *
 * Usage:
 *   router.get('/iocs', requireAuth, requirePermission('iocs:read'), handler)
 *   router.post('/iocs', requireAuth, requirePermission('iocs:write'), handler)
 */
export function requirePermission(...permissions: string[]) {
    return async (c: Context, next: Next) => {
        const user = c.get('user');
        if (!user) throw new HTTPException(401, { message: 'Authentication required' });

        try {
            const { hasAnyPermission, resolvePermissions } = await import('../services/rbacService');

            // Ensure permissions are resolved
            let userPerms = user.permissions;
            if (!userPerms || userPerms.length === 0) {
                userPerms = await resolvePermissions(user.role);
                user.permissions = userPerms;
                c.set('user', user);
            }

            if (!hasAnyPermission(userPerms, permissions)) {
                throw new HTTPException(403, {
                    message: `Access denied. Required permission: ${permissions.join(' or ')}`,
                });
            }
        } catch (err) {
            if (err instanceof HTTPException) throw err;
            // RBAC service failure — fall back to role-based check (admin always passes)
            if (user.role !== 'admin') {
                throw new HTTPException(403, {
                    message: 'Permission check unavailable. Contact administrator.',
                });
            }
        }

        await next();
    };
}

// Legacy export for backward compatibility
export const authMiddleware = requireAuth;
export default authMiddleware;

// ============================================================================
// Auth API Routes
// ============================================================================

export const authRouter = new Hono();

authRouter.post('/login', async (c) => {
    const body = await c.req.json<{ username?: string; password?: string; api_key?: string }>();

    // ── 1. API Key login ──────────────────────────────────────────────────
    if (body.api_key && API_KEYS.has(body.api_key)) {
        const keyInfo = API_KEYS.get(body.api_key)!;
        const token = createJWT({
            sub: `key:${body.api_key.substring(0, 8)}`,
            name: keyInfo.name,
            role: keyInfo.role,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });
        return c.json({ success: true, token, user: { name: keyInfo.name, role: keyInfo.role }, expiresIn: '24h' });
    }

    // ── 2. Credential login (DB user lookup) ──────────────────────────────
    if (body.username && body.password) {
        try {
            const { eq } = await import('@rinjani/db');
            const { db } = await import('@rinjani/db');
            const { users } = await import('@rinjani/db/schema');
            const { verifyPassword } = await import('../services/userService');

            // Look up user by email (username field is email on the login form)
            const [row] = await db.select().from(users).where(eq(users.email, body.username)).limit(1);

            if (row && row.passwordHash) {
                if (verifyPassword(body.password, row.passwordHash)) {
                    if (!row.isActive) {
                        return c.json({ success: false, error: 'Account is deactivated. Contact administrator.' }, 403);
                    }

                    const role = ((row.roles as string[]) || ['viewer'])[0] as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
                    const token = createJWT({
                        sub: row.id,
                        name: row.name,
                        role,
                        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
                    });

                    // Update lastLogin timestamp
                    await db.update(users).set({ lastLogin: new Date() }).where(eq(users.id, row.id));

                    return c.json({
                        success: true,
                        token,
                        user: { id: row.id, name: row.name, role, email: row.email },
                        expiresIn: '24h',
                    });
                }
                // Password wrong — fall through to 401
            }
        } catch (err) {
            console.error('[Auth] DB login lookup failed:', (err as Error).message);
            return c.json({ success: false, error: 'Authentication service unavailable' }, 503);
        }
    }

    return c.json({ success: false, error: 'Invalid credentials' }, 401);
});

// ── Register endpoint ─────────────────────────────────────────────────────
authRouter.post('/register', async (c) => {
    const body = await c.req.json<{
        email: string;
        password: string;
        name: string;
        role?: string;
    }>();

    if (!body.email || !body.password || !body.name) {
        return c.json({ success: false, error: 'Email, password, and name are required' }, 400);
    }

    if (body.password.length < 8) {
        return c.json({ success: false, error: 'Password must be at least 8 characters' }, 400);
    }

    try {
        const { db, eq } = await import('@rinjani/db');
        const { users } = await import('@rinjani/db/schema');
        const { hashPassword, generateApiToken } = await import('../services/userService');
        const { randomUUID } = await import('crypto');

        // Check duplicate email
        const [existing] = await db.select().from(users).where(eq(users.email, body.email)).limit(1);
        if (existing) {
            // If user exists but has no password, set it (first-time password setup)
            if (!existing.passwordHash) {
                const passwordHash = hashPassword(body.password);
                await db.update(users).set({ passwordHash, updatedAt: new Date() }).where(eq(users.id, existing.id));

                const role = ((existing.roles as string[]) || ['viewer'])[0] as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer';
                const token = createJWT({
                    sub: existing.id,
                    name: existing.name,
                    role,
                    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
                });

                return c.json({
                    success: true,
                    token,
                    user: { id: existing.id, name: existing.name, role, email: existing.email },
                    credentials: { apiToken: existing.apiToken || '', keycloakSynced: false },
                    expiresIn: '24h',
                });
            }
            return c.json({ success: false, error: 'Email already registered. Use login instead.' }, 409);
        }

        const id = randomUUID();
        const now = new Date();
        const passwordHash = hashPassword(body.password);
        const apiToken = generateApiToken();
        const role = body.role || 'analyst';

        const [row] = await db.insert(users).values({
            id,
            email: body.email,
            name: body.name,
            roles: [role],
            permissions: [],
            isActive: true,
            passwordHash,
            apiToken,
            createdAt: now,
            updatedAt: now,
        }).returning();

        // Auto-login: issue a JWT
        const token = createJWT({
            sub: row.id,
            name: row.name,
            role: role as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer',
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });

        return c.json({
            success: true,
            token,
            user: { id: row.id, name: row.name, role, email: row.email },
            credentials: { apiToken, temporaryPassword: undefined, keycloakSynced: false },
            expiresIn: '24h',
        });
    } catch (err) {
        console.error('[Auth] Registration failed:', (err as Error).message);
        return c.json({ success: false, error: (err as Error).message }, 500);
    }
});

authRouter.get('/verify', requireAuth, async (c) => {
    const user = c.get('user');
    let dbUser: any = null;
    try {
        const { getUserById, listUsers } = await import('../services/userService');
        // 1. Direct ID lookup (works for real UUID-based users)
        try { dbUser = await getUserById(user.id); } catch { /* not a valid UUID */ }
        // 2. Fallback strategies for JWT format "user:admin"
        if (!dbUser && user.id.startsWith('user:')) {
            try {
                const username = user.id.slice(5); // "admin"
                const { users } = await listUsers({ limit: 100 });
                // 2a. Email prefix match
                dbUser = users.find((u: any) =>
                    u.email.toLowerCase().startsWith(username.toLowerCase())
                ) || null;
                // 2b. Name match (case-insensitive)
                if (!dbUser) {
                    dbUser = users.find((u: any) =>
                        u.name.toLowerCase() === user.name?.toLowerCase()
                    ) || null;
                }
                // 2c. Role-based fallback — find first user with matching role
                if (!dbUser) {
                    dbUser = users.find((u: any) =>
                        u.roles?.includes(user.role) && u.isActive
                    ) || null;
                }
            } catch { /* listUsers failed */ }
        }
    } catch { /* module import failed */ }
    return c.json({
        success: true,
        user: {
            id: dbUser?.id || user.id,
            name: dbUser?.name || user.name,
            role: user.role,
            method: user.method,
            avatarUrl: dbUser?.avatarUrl || null,
        },
    });
});

authRouter.post('/refresh', requireAuth, (c) => {
    const user = c.get('user');
    const token = createJWT({
        sub: user.id,
        name: user.name,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
    });
    return c.json({ success: true, token, expiresIn: '24h' });
});

authRouter.get('/my-tenants', requireAuth, async (c) => {
    const user = c.get('user');
    try {
        const { getUserTenants } = await import('../services/federation');
        const tenants = await getUserTenants(user.id);
        return c.json({ success: true, data: tenants });
    } catch {
        return c.json({ success: true, data: [] });
    }
});

authRouter.post('/tenant-select', requireAuth, async (c) => {
    const user = c.get('user');
    const { tenantId } = await c.req.json<{ tenantId: string }>();
    if (!tenantId) return c.json({ success: false, error: 'tenantId is required' }, 400);

    try {
        const { getUserTenants } = await import('../services/federation');
        const memberships = await getUserTenants(user.id);
        const membership = memberships.find(m => m.tenantId === tenantId);
        if (!membership) {
            return c.json({ success: false, error: 'You are not a member of this tenant' }, 403);
        }

        const token = createJWT({
            sub: user.id,
            name: user.name,
            role: user.role,
            tenantId: membership.tenantId,
            tenantRole: membership.tenantRole,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });

        return c.json({
            success: true,
            token,
            tenant: {
                id: membership.tenantId,
                name: membership.tenantName,
                slug: membership.tenantSlug,
                role: membership.tenantRole,
            },
            expiresIn: '24h',
        });
    } catch (err) {
        return c.json({ success: false, error: (err as Error).message }, 500);
    }
});
