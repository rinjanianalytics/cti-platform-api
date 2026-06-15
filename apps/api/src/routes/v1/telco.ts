/**
 * /v1/telco — Telco threat-domain entities (B1.1).
 *
 *   network-elements/      HSS, UDM, AMF, MME, OCS, PCRF, …
 *   signaling-interfaces/  SS7, Diameter, GTP reference points
 *   fraud-schemes/         SIM-swap, IRSF, Wangiri, …
 *
 * Each resource: POST (upsert by ref_id) · GET list (filter + q) · GET :id ·
 * DELETE :id. Reads open to any authenticated user; writes require
 * admin/analyst/developer. The 5G THREAT model lives in /v1/fight (MITRE
 * FiGHT) — this is the ENTITY layer. Graph bridging + GSMA/3GPP mapping are
 * B1.2 / B1.3.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import {
    upsertNetworkElement, listNetworkElements, getNetworkElement, deleteNetworkElement,
    upsertSignalingInterface, listSignalingInterfaces, getSignalingInterface, deleteSignalingInterface,
    upsertFraudScheme, listFraudSchemes, getFraudScheme, deleteFraudScheme,
} from '../../services/telcoStore';

const log = createLogger('Telco');
const router = new Hono();
const WRITE_ROLES = ['admin', 'analyst', 'developer'] as const;

router.use('*', requireAuth);

// Shared field fragments ------------------------------------------------------
const refId = z.string().min(1).max(255);
const name = z.string().min(1).max(500);
const jsonStrArray = z.array(z.string()).default([]);
const jsonObjArray = z.array(z.record(z.unknown())).default([]);
const stixId = z.string().max(255).optional();

const NetworkElementBody = z.object({
    refId,
    name,
    stixId,
    description: z.string().optional(),
    elementType: z.string().min(1).max(100),
    architectureSegment: z.string().max(64).optional(),
    vendor: jsonStrArray,
    interfaces: jsonObjArray,
    externalReferences: jsonObjArray,
    labels: jsonStrArray,
});

const SignalingInterfaceBody = z.object({
    refId,
    name,
    stixId,
    description: z.string().optional(),
    protocol: z.string().min(1).max(50),
    referencePoint: z.string().max(100).optional(),
    specRef: z.string().max(255).optional(),
    externalReferences: jsonObjArray,
    labels: jsonStrArray,
});

const FraudSchemeBody = z.object({
    refId,
    name,
    stixId,
    description: z.string().optional(),
    schemeType: z.string().min(1).max(100),
    monetization: z.string().optional(),
    gsmaFsCategories: jsonStrArray,
    killChainPhases: jsonObjArray,
    externalReferences: jsonObjArray,
    labels: jsonStrArray,
});

function parseOrThrow<T>(schema: z.ZodType<T>, raw: unknown): T {
    const parsed = schema.safeParse(raw);
    if (!parsed.success) {
        throw new ValidationError('Invalid request body', {
            issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
        });
    }
    return parsed.data;
}

// ── Network elements ────────────────────────────────────────────────────────
router.post('/telco/network-elements', requireRole(...WRITE_ROLES), async (c) => {
    const body = parseOrThrow(NetworkElementBody, await c.req.json().catch(() => ({})));
    const row = await upsertNetworkElement(body);
    log.info('Network element upserted', { id: row.id, refId: row.refId });
    return c.json({ success: true, data: row }, 201);
});
router.get('/telco/network-elements', async (c) => {
    const rows = await listNetworkElements({
        elementType: c.req.query('elementType'),
        q: c.req.query('q'),
        limit: c.req.query('limit') ? Number(c.req.query('limit')) : undefined,
    });
    return c.json({ success: true, data: rows, count: rows.length });
});
router.get('/telco/network-elements/:id', async (c) => {
        const { id } = c.req.param();
    const row = await getNetworkElement(id);
    if (!row) throw new NotFoundError('NetworkElement', id);
    return c.json({ success: true, data: row });
});
router.delete('/telco/network-elements/:id', requireRole(...WRITE_ROLES), async (c) => {
        const { id } = c.req.param();
    const ok = await deleteNetworkElement(id);
    if (!ok) throw new NotFoundError('NetworkElement', id);
    return c.json({ success: true, data: { id: id, deleted: true } });
});

// ── Signaling interfaces ────────────────────────────────────────────────────
router.post('/telco/signaling-interfaces', requireRole(...WRITE_ROLES), async (c) => {
    const body = parseOrThrow(SignalingInterfaceBody, await c.req.json().catch(() => ({})));
    const row = await upsertSignalingInterface(body);
    log.info('Signaling interface upserted', { id: row.id, refId: row.refId });
    return c.json({ success: true, data: row }, 201);
});
router.get('/telco/signaling-interfaces', async (c) => {
    const rows = await listSignalingInterfaces({
        protocol: c.req.query('protocol'),
        q: c.req.query('q'),
        limit: c.req.query('limit') ? Number(c.req.query('limit')) : undefined,
    });
    return c.json({ success: true, data: rows, count: rows.length });
});
router.get('/telco/signaling-interfaces/:id', async (c) => {
        const { id } = c.req.param();
    const row = await getSignalingInterface(id);
    if (!row) throw new NotFoundError('SignalingInterface', id);
    return c.json({ success: true, data: row });
});
router.delete('/telco/signaling-interfaces/:id', requireRole(...WRITE_ROLES), async (c) => {
        const { id } = c.req.param();
    const ok = await deleteSignalingInterface(id);
    if (!ok) throw new NotFoundError('SignalingInterface', id);
    return c.json({ success: true, data: { id: id, deleted: true } });
});

// ── Fraud schemes ───────────────────────────────────────────────────────────
router.post('/telco/fraud-schemes', requireRole(...WRITE_ROLES), async (c) => {
    const body = parseOrThrow(FraudSchemeBody, await c.req.json().catch(() => ({})));
    const row = await upsertFraudScheme(body);
    log.info('Fraud scheme upserted', { id: row.id, refId: row.refId });
    return c.json({ success: true, data: row }, 201);
});
router.get('/telco/fraud-schemes', async (c) => {
    const rows = await listFraudSchemes({
        schemeType: c.req.query('schemeType'),
        q: c.req.query('q'),
        limit: c.req.query('limit') ? Number(c.req.query('limit')) : undefined,
    });
    return c.json({ success: true, data: rows, count: rows.length });
});
router.get('/telco/fraud-schemes/:id', async (c) => {
        const { id } = c.req.param();
    const row = await getFraudScheme(id);
    if (!row) throw new NotFoundError('FraudScheme', id);
    return c.json({ success: true, data: row });
});
router.delete('/telco/fraud-schemes/:id', requireRole(...WRITE_ROLES), async (c) => {
        const { id } = c.req.param();
    const ok = await deleteFraudScheme(id);
    if (!ok) throw new NotFoundError('FraudScheme', id);
    return c.json({ success: true, data: { id: id, deleted: true } });
});

export default router;

// Exported for unit tests — the zod bodies are the validation contract.
export const __schemas = { NetworkElementBody, SignalingInterfaceBody, FraudSchemeBody };
