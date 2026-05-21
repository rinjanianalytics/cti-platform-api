/**
 * User Management API Routes
 * 
 * Provides CRUD operations for user management with RBAC.
 * Admin-only access for user management operations.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole, createJWT } from '../middleware/auth';
import { NotFoundError, ValidationError, ConflictError, ForbiddenError } from '../lib/errors';
import { CreateUserSchema, UpdateUserSchema, UserListQuerySchema } from '../lib/schemas';

const users = new Hono();

// ============================================================================
// GET /users/me — current authenticated user
//
// Returns the JWT-resolved user plus DB profile (avatarUrl, real email) when
// the JWT `sub` is a real UUID. Replaces the dashboard hack that listed every
// user and fuzzy-matched email to find the current one.
// ============================================================================

users.get('/me', requireAuth, async (c) => {
    const u = c.get('user');
    let profile: { avatarUrl: string | null; email?: string; lastLogin?: string | null } | null = null;

    try {
        const { getUserById } = await import('../services/userService');
        const dbUser = await getUserById(u.id);
        if (dbUser) {
            profile = {
                avatarUrl: (dbUser.avatarUrl as string | null) ?? null,
                email: (dbUser.email as string) ?? undefined,
                lastLogin: (dbUser.lastLogin as string | null) ?? null,
            };
        }
    } catch {
        // Non-UUID sub (e.g. `key:abc123` for API-key sessions) or DB miss — silent fall-through.
    }

    return c.json({
        success: true,
        data: {
            id: u.id,
            name: u.name,
            role: u.role,
            method: u.method,
            tenantId: u.tenantId ?? null,
            tenantRole: u.tenantRole ?? null,
            permissions: u.permissions ?? [],
            avatarUrl: profile?.avatarUrl ?? null,
            email: profile?.email ?? null,
            lastLogin: profile?.lastLogin ?? null,
        },
    });
});

// ============================================================================
// In-Memory User Store (for demo - replace with database in production)
// ============================================================================

interface User {
    id: string;
    email: string;
    name: string;
    role: 'admin' | 'analyst' | 'viewer';
    status: 'active' | 'inactive' | 'pending';
    createdAt: string;
    lastLogin?: string;
}

const USER_STORE: User[] = [
    { id: 'usr-001', email: 'admin@rinjani.io', name: 'Administrator', role: 'admin', status: 'active', createdAt: '2024-01-01T00:00:00Z', lastLogin: new Date().toISOString() },
    { id: 'usr-002', email: 'analyst@rinjani.io', name: 'Security Analyst', role: 'analyst', status: 'active', createdAt: '2024-06-15T10:30:00Z', lastLogin: '2024-12-20T14:15:00Z' },
    { id: 'usr-003', email: 'viewer@rinjani.io', name: 'Dashboard Viewer', role: 'viewer', status: 'active', createdAt: '2024-09-01T08:00:00Z' },
    { id: 'usr-004', email: 'pending@rinjani.io', name: 'New User', role: 'viewer', status: 'pending', createdAt: new Date().toISOString() },
];

// ============================================================================
// User CRUD Endpoints
// ============================================================================

/**
 * GET /users
 * List all users (admin only)
 */
users.get('/', requireAuth, requireRole('admin'), async (c) => {
    const { status, role } = UserListQuerySchema.parse(c.req.query());

    let filtered = [...USER_STORE];

    if (status && status !== 'all') {
        filtered = filtered.filter(u => u.status === status);
    }
    if (role && role !== 'all') {
        filtered = filtered.filter(u => u.role === role);
    }

    return c.json({
        success: true,
        data: {
            users: filtered,
            total: filtered.length,
        },
    });
});

/**
 * GET /users/:id
 * Get single user details
 */
users.get('/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const user = USER_STORE.find(u => u.id === id);

    if (!user) {
        throw new NotFoundError('User', id);
    }

    return c.json({ success: true, data: user });
});

/**
 * POST /users
 * Create new user (admin only)
 */
users.post('/', requireAuth, requireRole('admin'), async (c) => {
    const body = CreateUserSchema.parse(await c.req.json().catch(() => ({})));

    // Check if email exists
    if (USER_STORE.some(u => u.email === body.email)) {
        throw new ConflictError('Email already exists');
    }

    const newUser: User = {
        id: `usr-${Date.now().toString(36)}`,
        email: body.email,
        name: body.name,
        role: body.role,
        status: 'pending',
        createdAt: new Date().toISOString(),
    };

    USER_STORE.push(newUser);

    return c.json({ success: true, data: newUser }, 201);
});

/**
 * PUT /users/:id
 * Update user (admin only)
 */
users.put('/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const body = UpdateUserSchema.parse(await c.req.json().catch(() => ({})));

    const index = USER_STORE.findIndex(u => u.id === id);
    if (index === -1) {
        throw new NotFoundError('User', id);
    }

    // Prevent role changes on own account
    const currentUser = c.get('user');
    if (id === currentUser.id && body.role && body.role !== USER_STORE[index].role) {
        throw new ForbiddenError('Cannot change your own role');
    }

    USER_STORE[index] = {
        ...USER_STORE[index],
        ...body,
        id: USER_STORE[index].id, // Prevent ID change
        createdAt: USER_STORE[index].createdAt, // Prevent createdAt change
    };

    return c.json({ success: true, data: USER_STORE[index] });
});

/**
 * DELETE /users/:id
 * Delete user (admin only)
 */
users.delete('/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');

    const index = USER_STORE.findIndex(u => u.id === id);
    if (index === -1) {
        throw new NotFoundError('User', id);
    }

    // Prevent self-deletion
    const currentUser = c.get('user');
    if (id === currentUser.id) {
        throw new ForbiddenError('Cannot delete your own account');
    }

    USER_STORE.splice(index, 1);

    return c.json({ success: true, message: 'User deleted' });
});

/**
 * POST /users/:id/activate
 * Activate a pending user
 */
users.post('/:id/activate', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const index = USER_STORE.findIndex(u => u.id === id);

    if (index === -1) {
        throw new NotFoundError('User', id);
    }

    USER_STORE[index].status = 'active';

    return c.json({ success: true, data: USER_STORE[index] });
});

/**
 * POST /users/:id/deactivate
 * Deactivate a user
 */
users.post('/:id/deactivate', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const index = USER_STORE.findIndex(u => u.id === id);

    if (index === -1) {
        throw new NotFoundError('User', id);
    }

    // Prevent self-deactivation
    const currentUser = c.get('user');
    if (id === currentUser.id) {
        throw new ForbiddenError('Cannot deactivate your own account');
    }

    USER_STORE[index].status = 'inactive';

    return c.json({ success: true, data: USER_STORE[index] });
});

/**
 * GET /users/roles
 * Get available roles
 */
users.get('/roles/list', requireAuth, async (c) => {
    return c.json({
        success: true,
        data: [
            { id: 'admin', name: 'Administrator', description: 'Full system access' },
            { id: 'analyst', name: 'Security Analyst', description: 'Can view and edit threat data' },
            { id: 'viewer', name: 'Viewer', description: 'Read-only access to dashboards' },
        ],
    });
});

export default users;
