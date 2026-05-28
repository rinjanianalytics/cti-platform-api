/**
 * Admin Routes — Federation & Migrations
 *
 * Admin endpoints for managing multi-tenant federation and database migrations.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { createLogger } from '../../lib/logger';
import { NotFoundError } from '../../lib/errors';
import {
    CreateTenantSchema, AddPeerSchema, RollbackSchema, RescoreSchema,
} from '../../lib/schemas';
import {
    createTenant, suspendTenant, reactivateTenant, updateTenantConfig,
    getTenant, listTenants, addPeer, listPeers,
    testPeerConnection, getFederationStats,
    listTenantMembers, addTenantMember, removeTenantMember, updateMemberRole,
    inviteTenantMember,
} from '../../services/federation';
import { runMigrations, getMigrationStatus, rollbackMigrations } from '../../services/migrations';
import { computeCompositeScore, rescoreAll, getScoreSummary } from '../../services/scoringEngine';

const log = createLogger('admin-federation');
const router = new Hono();

// ============================================================================
// Federation
// ============================================================================

router.get('/federation/stats', requireAuth, requireRole('admin'), async (c) => {
    const stats = await getFederationStats();
    return c.json({ success: true, data: stats });
});

router.get('/federation/tenants', requireAuth, requireRole('admin'), async (c) => {
    const tenants = await listTenants();
    return c.json({ success: true, data: tenants });
});

router.post('/federation/tenants', requireAuth, requireRole('admin'), async (c) => {
    const { name, slug, tier, config } = CreateTenantSchema.parse(await c.req.json());
    const tenant = await createTenant(name, slug, tier, config);
    return c.json({ success: true, data: tenant }, 201);
});

router.get('/federation/tenants/:id', requireAuth, requireRole('admin'), async (c) => {
    const tenant = await getTenant(c.req.param('id')!);
    if (!tenant) throw new NotFoundError('Tenant', c.req.param('id')!);
    return c.json({ success: true, data: tenant });
});

router.post('/federation/tenants/:id/suspend', requireAuth, requireRole('admin'), async (c) => {
    await suspendTenant(c.req.param('id')!);
    return c.json({ success: true, message: 'Tenant suspended' });
});

router.post('/federation/tenants/:id/reactivate', requireAuth, requireRole('admin'), async (c) => {
    await reactivateTenant(c.req.param('id')!);
    return c.json({ success: true, message: 'Tenant reactivated' });
});

router.patch('/federation/tenants/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id')!;
    const body = await c.req.json<{ tier?: string; config?: Record<string, unknown> }>();
    const updated = await updateTenantConfig(id, body);
    return c.json({ success: true, data: updated });
});

// Peers
router.get('/federation/tenants/:id/peers', requireAuth, requireRole('admin'), async (c) => {
    const peers = await listPeers(c.req.param('id')!);
    return c.json({ success: true, data: peers });
});

router.post('/federation/tenants/:id/peers', requireAuth, requireRole('admin'), async (c) => {
    const { name, url, apiKey, trustLevel } = AddPeerSchema.parse(await c.req.json());
    const peer = await addPeer(c.req.param('id')!, name, url, apiKey, trustLevel);
    return c.json({ success: true, data: peer }, 201);
});

router.post('/federation/peers/:peerId/test', requireAuth, requireRole('admin'), async (c) => {
    const result = await testPeerConnection(c.req.param('peerId')!);
    return c.json({ success: true, data: result });
});

// Tenant Members
router.get('/federation/tenants/:id/members', requireAuth, requireRole('admin'), async (c) => {
    const members = await listTenantMembers(c.req.param('id')!);
    return c.json({ success: true, data: members });
});

router.post('/federation/tenants/:id/members', requireAuth, requireRole('admin'), async (c) => {
    const body = await c.req.json<{ userId?: string; email?: string; name?: string; role?: string }>();
    const tenantId = c.req.param('id')!;
    const role = body.role || 'viewer';

    // Invite mode: create user + join tenant + KC sync
    if (body.email) {
        const result = await inviteTenantMember(tenantId, body.email, body.name || body.email, role);
        return c.json({ success: true, data: result }, 201);
    }

    // Existing user mode
    if (!body.userId) return c.json({ success: false, error: 'userId or email is required' }, 400);
    const member = await addTenantMember(tenantId, body.userId, role);
    return c.json({ success: true, data: member }, 201);
});

router.delete('/federation/tenants/:id/members/:userId', requireAuth, requireRole('admin'), async (c) => {
    await removeTenantMember(c.req.param('id')!, c.req.param('userId')!);
    return c.json({ success: true, message: 'Member removed' });
});

router.patch('/federation/tenants/:id/members/:userId/role', requireAuth, requireRole('admin'), async (c) => {
    const { role } = await c.req.json<{ role: string }>();
    if (!role) return c.json({ success: false, error: 'role is required' }, 400);
    await updateMemberRole(c.req.param('id')!, c.req.param('userId')!, role);
    return c.json({ success: true, message: 'Role updated' });
});

// ============================================================================
// Migrations
// ============================================================================

router.get('/migrations/status', requireAuth, requireRole('admin'), async (c) => {
    const status = await getMigrationStatus();
    return c.json({ success: true, data: status });
});

router.post('/migrations/run', requireAuth, requireRole('admin'), async (c) => {
    const result = await runMigrations();
    return c.json({ success: true, data: result });
});

router.post('/migrations/rollback', requireAuth, requireRole('admin'), async (c) => {
    const { count } = RollbackSchema.parse(await c.req.json().catch(() => ({})));
    const result = await rollbackMigrations(count);
    return c.json({ success: true, data: result });
});

// ============================================================================
// Scoring Engine
// ============================================================================

router.get('/scoring/summary', requireAuth, requireRole('admin'), async (c) => {
    const summary = await getScoreSummary();
    return c.json({
        success: true, data: {
            totalScored: summary.total,
            averageScore: summary.avgScore,
            distribution: summary.distribution,
            timestamp: new Date().toISOString(),
        }
    });
});

router.get('/scoring/ioc/:id', requireAuth, requireRole('admin'), async (c) => {
    const score = await computeCompositeScore(c.req.param('id')!);
    return c.json({ success: true, data: score });
});

router.post('/scoring/rescore', requireAuth, requireRole('admin'), async (c) => {
    const { batchSize } = RescoreSchema.parse(await c.req.json().catch(() => ({})));
    log.info('Batch rescore triggered', { batchSize });
    const result = await rescoreAll(batchSize);
    return c.json({ success: true, data: result });
});

export default router;
