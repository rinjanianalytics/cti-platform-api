/**
 * Admin User Management Routes
 *
 * Full CRUD for user management, role definitions, permission modules, 
 * and API token management. All endpoints require admin authentication.
 *
 * Mounts at: /admin/users/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError, ConflictError, ForbiddenError } from '../../lib/errors';
import {
    AdminCreateUserSchema, AdminUpdateUserSchema,
    AdminCreateRoleSchema, AdminUpdateRoleSchema,
    AdminCreatePermModuleSchema, AdminUpdatePermModuleSchema,
    AdminUserListSchema, ChangePasswordSchema,
} from '../../lib/schemas';
import { logAudit } from '../../services/auditService';
import {
    // User CRUD
    listUsers,
    getUserById,
    createUser,
    updateUser,
    deleteUser,
    purgeUser,
    activateUser,
    deactivateUser,
    regenerateApiToken,
    changePassword,
    // Role CRUD
    listRoles,
    getRoleById,
    createRole,
    updateRole,
    deleteRole,
    // Permission Module CRUD
    listPermissionModules,
    createPermissionModule,
    updatePermissionModule,
    deletePermissionModule,
    // Types
    type UserListFilters,
} from '../../services/userService';

const router = new Hono();

// ============================================================================
// User CRUD
// ============================================================================

/** GET /users — List users (paginated, filterable) */
router.get('/users', requireAuth, requireRole('admin'), async (c) => {
    const parsed = AdminUserListSchema.parse(c.req.query());
    const filters: UserListFilters = {
        role: parsed.role,
        status: parsed.status,
        search: parsed.search,
        page: parsed.page,
        limit: parsed.limit,
    };

    const result = await listUsers(filters);

    return c.json({
        success: true,
        data: result,
    });
});

/** GET /users/roles/list — Available roles & permission modules (DB-backed) */
router.get('/users/roles/list', requireAuth, requireRole('admin'), async (c) => {
    const [roles, permissionModules] = await Promise.all([
        listRoles(),
        listPermissionModules(),
    ]);

    return c.json({
        success: true,
        data: {
            roles,
            permissionModules,
        },
    });
});

/** GET /users/:id — Get single user */
router.get('/users/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const user = await getUserById(id);

    if (!user) {
        throw new NotFoundError('User', id);
    }

    return c.json({ success: true, data: user });
});

/** POST /users — Create user (auto-generates API token) */
router.post('/users', requireAuth, requireRole('admin'), async (c) => {
    const body = AdminCreateUserSchema.parse(await c.req.json());

    // Validate role exists in DB
    const roleDef = await getRoleById(body.role);
    if (!roleDef) {
        const allRoles = await listRoles();
        throw new ValidationError(`Invalid role. Must be one of: ${allRoles.map(r => r.id).join(', ')}`);
    }

    try {
        const user = await createUser({
            email: body.email,
            name: body.name,
            role: body.role,
            permissions: body.permissions,
        });
        logAudit({ entityType: 'user', entityId: user.id, action: 'create', userId: c.get('user').id, source: 'admin' });
        return c.json({ success: true, data: user }, 201);
    } catch (err) {
        if ((err as Error).message?.includes('Email already exists')) {
            throw new ConflictError((err as Error).message);
        }
        throw err;
    }
});

/** PUT /users/:id — Update user */
router.put('/users/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const body = AdminUpdateUserSchema.parse(await c.req.json());

    // Prevent self-role change
    const currentUser = c.get('user');
    if (currentUser.id === id && body.role) {
        throw new ForbiddenError('Cannot change your own role');
    }

    if (body.role) {
        const roleDef = await getRoleById(body.role);
        if (!roleDef) {
            const allRoles = await listRoles();
            throw new ValidationError(`Invalid role. Must be one of: ${allRoles.map(r => r.id).join(', ')}`);
        }
    }

    const user = await updateUser(id, body);
    if (!user) {
        throw new NotFoundError('User', id);
    }

    logAudit({ entityType: 'user', entityId: id, action: 'update', userId: c.get('user').id, source: 'admin', changes: { after: body } });
    return c.json({ success: true, data: user });
});

/** DELETE /users/:id — Soft-delete (deactivate) user. Reversible via /activate. */
router.delete('/users/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');

    // Prevent self-deletion
    const currentUser = c.get('user');
    if (currentUser.id === id) {
        throw new ForbiddenError('Cannot delete your own account');
    }

    const ok = await deleteUser(id);
    if (!ok) {
        throw new NotFoundError('User', id);
    }

    logAudit({ entityType: 'user', entityId: id, action: 'delete', userId: c.get('user').id, source: 'admin' });
    return c.json({ success: true, message: 'User deactivated' });
});

/**
 * DELETE /users/:id/purge — HARD delete. Removes the row.
 * Use for permanent bans / GDPR right-to-erasure / test-account cleanup.
 * Cascades: org memberships, API keys, sessions, oauth identities (all drop).
 * Severs: playbooks.created_by and sightings.created_by set to NULL so
 * historic records keep working.
 * Preserves: audit_logs (no FK — audit trail outlives the user).
 */
router.delete('/users/:id/purge', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');

    const currentUser = c.get('user');
    if (currentUser.id === id) {
        throw new ForbiddenError('Cannot purge your own account');
    }

    const ok = await purgeUser(id);
    if (!ok) {
        throw new NotFoundError('User', id);
    }

    logAudit({ entityType: 'user', entityId: id, action: 'delete', userId: c.get('user').id, source: 'admin', metadata: { hard: true, reason: 'purge' } });
    return c.json({ success: true, message: 'User permanently deleted' });
});

// ============================================================================
// Status Toggles
// ============================================================================

/** POST /users/:id/activate — Re-activate a deactivated user */
router.post('/users/:id/activate', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const user = await activateUser(id);
    if (!user) {
        throw new NotFoundError('User', id);
    }
    return c.json({ success: true, data: user });
});

/** POST /users/:id/deactivate — Deactivate a user */
router.post('/users/:id/deactivate', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');

    const currentUser = c.get('user');
    if (currentUser.id === id) {
        throw new ForbiddenError('Cannot deactivate your own account');
    }

    const user = await deactivateUser(id);
    if (!user) {
        throw new NotFoundError('User', id);
    }
    return c.json({ success: true, data: user });
});

// ============================================================================
// API Token Management
// ============================================================================

/** POST /users/:id/regenerate-token — Regenerate a user's API token */
router.post('/users/:id/regenerate-token', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const result = await regenerateApiToken(id);
    if (!result) {
        throw new NotFoundError('User', id);
    }
    return c.json({ success: true, data: result });
});

// ============================================================================
// Avatar Upload
// ============================================================================

/** POST /users/:id/avatar — Update user avatar (self or admin) */
router.post('/users/:id/avatar', requireAuth, async (c) => {
    const id = c.req.param('id');
    const authUser = c.get('user');

    // Users can update their own avatar; admins can update anyone's
    if (authUser.id !== id && authUser.role !== 'admin') {
        throw new ForbiddenError('You can only update your own avatar');
    }

    const body = await c.req.json();
    const avatarUrl = body.avatarUrl;

    if (typeof avatarUrl !== 'string' && avatarUrl !== null) {
        throw new ValidationError('avatarUrl must be a string or null');
    }

    // Validate size (max ~500KB for base64)
    if (avatarUrl && avatarUrl.length > 500000) {
        throw new ValidationError('Avatar too large. Maximum size is ~375KB.');
    }

    const user = await updateUser(id, { avatarUrl: avatarUrl || null });
    if (!user) {
        throw new NotFoundError('User', id);
    }

    logAudit({ entityType: 'user', entityId: id, action: 'update', userId: c.get('user').id, source: 'admin', metadata: { reason: 'avatar_upload' } });
    return c.json({ success: true, data: user });
});

// ============================================================================
// Change Password
// ============================================================================

/** POST /users/:id/change-password — Change user password */
router.post('/users/:id/change-password', requireAuth, async (c) => {
    const id = c.req.param('id');
    const authUser = c.get('user');

    // Users can change their own password; admins can change anyone's
    if (authUser.id !== id && authUser.role !== 'admin') {
        throw new ForbiddenError('You can only change your own password');
    }

    const body = ChangePasswordSchema.parse(await c.req.json());
    const result = await changePassword(id, body.currentPassword, body.newPassword);

    if (!result.success) {
        throw new ValidationError(result.error || 'Password change failed');
    }

    logAudit({ entityType: 'user', entityId: id, action: 'update', userId: authUser.id, source: 'admin', metadata: { reason: 'password_change' } });
    return c.json({ success: true, message: 'Password changed successfully' });
});

// ============================================================================
// Role CRUD (DB-backed)
// ============================================================================

/** POST /users/roles — Create a new role */
router.post('/users/roles', requireAuth, requireRole('admin'), async (c) => {
    const body = AdminCreateRoleSchema.parse(await c.req.json());

    try {
        const role = await createRole({
            id: body.id,
            name: body.name,
            description: body.description || '',
            defaultPermissions: body.defaultPermissions || [],
        });
        return c.json({ success: true, data: role }, 201);
    } catch (err) {
        if ((err as Error).message?.includes('already exists')) {
            throw new ConflictError((err as Error).message);
        }
        throw err;
    }
});

/** PUT /users/roles/:id — Update a role */
router.put('/users/roles/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const body = AdminUpdateRoleSchema.parse(await c.req.json());

    const role = await updateRole(id, body);
    if (!role) {
        throw new NotFoundError('Role', id);
    }

    return c.json({ success: true, data: role });
});

/** DELETE /users/roles/:id — Delete a custom role (system roles protected) */
router.delete('/users/roles/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');

    try {
        const ok = await deleteRole(id);
        if (!ok) {
            throw new NotFoundError('Role', id);
        }
        return c.json({ success: true, message: 'Role deleted' });
    } catch (err) {
        if ((err as Error).message?.includes('system role')) {
            throw new ForbiddenError((err as Error).message);
        }
        throw err;
    }
});

// ============================================================================
// Permission Module CRUD (DB-backed)
// ============================================================================

/** POST /users/permissions — Create a permission module */
router.post('/users/permissions', requireAuth, requireRole('admin'), async (c) => {
    const body = AdminCreatePermModuleSchema.parse(await c.req.json());

    try {
        const mod = await createPermissionModule({
            id: body.id,
            name: body.name,
            icon: body.icon || 'settings',
            permissions: body.permissions || [],
        });
        return c.json({ success: true, data: mod }, 201);
    } catch (err) {
        if ((err as Error).message?.includes('already exists')) {
            throw new ConflictError((err as Error).message);
        }
        throw err;
    }
});

/** PUT /users/permissions/:id — Update a permission module */
router.put('/users/permissions/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');
    const body = AdminUpdatePermModuleSchema.parse(await c.req.json());

    const mod = await updatePermissionModule(id, body);
    if (!mod) {
        throw new NotFoundError('PermissionModule', id);
    }

    return c.json({ success: true, data: mod });
});

/** DELETE /users/permissions/:id — Delete a custom permission module */
router.delete('/users/permissions/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id');

    try {
        const ok = await deletePermissionModule(id);
        if (!ok) {
            throw new NotFoundError('PermissionModule', id);
        }
        return c.json({ success: true, message: 'Permission module deleted' });
    } catch (err) {
        if ((err as Error).message?.includes('system permission module')) {
            throw new ForbiddenError((err as Error).message);
        }
        throw err;
    }
});

export default router;
