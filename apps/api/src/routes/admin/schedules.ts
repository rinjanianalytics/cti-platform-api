/**
 * Admin scheduled-job control.
 *
 * Lets admins toggle code-defined repeatable jobs on/off and pick a curated
 * interval preset, without redeploying. Cron is intentionally not free-form
 * (bad cron = trivial self-DoS).
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError } from '../../lib/errors';
import { logAudit } from '../../services/auditService';
import {
    upsertOverride,
    INTERVAL_PRESETS,
    isIntervalPreset,
} from '../../services/scheduledJobOverrides';
import {
    JOB_REGISTRY,
    getScheduledJobsAdminView,
    reconcileScheduledJobByKey,
    triggerScheduledJobNow,
} from '../../queues/scheduler';

const router = new Hono();

const PatchSchema = z.object({
    enabled: z.boolean().optional(),
    intervalPreset: z.union([
        z.enum(Object.keys(INTERVAL_PRESETS) as [string, ...string[]]),
        z.null(),
    ]).optional(),
    payload: z.record(z.string(), z.unknown()).nullable().optional(),
});

/** GET /admin/schedules — list every scheduled job + override + effective cron. */
router.get('/schedules', requireAuth, requireRole('admin'), async (c) => {
    const jobs = await getScheduledJobsAdminView();
    return c.json({
        success: true,
        data: {
            jobs,
            intervalPresets: INTERVAL_PRESETS,
            count: jobs.length,
        },
    });
});

/** PATCH /admin/schedules/:key — upsert override; reconciles BullMQ on save. */
router.patch('/schedules/:key', requireAuth, requireRole('admin'), async (c) => {
    const key = c.req.param('key');
    if (!JOB_REGISTRY.some(r => r.key === key)) {
        throw new NotFoundError('ScheduledJob', key);
    }

    const body = PatchSchema.parse(await c.req.json());
    if (body.intervalPreset !== undefined && body.intervalPreset !== null && !isIntervalPreset(body.intervalPreset)) {
        throw new ValidationError(`Invalid intervalPreset: ${body.intervalPreset}`);
    }

    const user = c.get('user');
    const override = await upsertOverride(key, {
        enabled: body.enabled,
        intervalPreset: body.intervalPreset,
        payload: body.payload,
    }, user?.id ?? null);

    // Push the new schedule into BullMQ immediately — both API and worker
    // processes read the same Redis state, so the worker picks it up on the
    // next tick without any cross-process messaging.
    const result = await reconcileScheduledJobByKey(key);

    logAudit({
        entityType: 'user',  // closest existing audit-entity; sched jobs aren't a tracked entity
        entityId: user?.id ?? '00000000-0000-0000-0000-000000000000',
        action: 'update',
        userId: user?.id,
        source: 'admin',
        metadata: {
            scope: 'scheduled-job',
            jobKey: key,
            enabled: override.enabled,
            intervalPreset: override.intervalPreset,
        },
    });

    return c.json({
        success: true,
        data: {
            override: {
                jobKey: override.jobKey,
                enabled: override.enabled,
                intervalPreset: override.intervalPreset,
                payload: override.payload,
                updatedAt: override.updatedAt,
                updatedBy: override.updatedBy,
            },
            reconciled: result,
        },
    });
});

/** POST /admin/schedules/:key/run-now — fire one ad-hoc run. */
router.post('/schedules/:key/run-now', requireAuth, requireRole('admin'), async (c) => {
    const key = c.req.param('key');
    if (!JOB_REGISTRY.some(r => r.key === key)) {
        throw new NotFoundError('ScheduledJob', key);
    }
    const result = await triggerScheduledJobNow(key);
    return c.json({ success: true, data: { ...result, key } });
});

export default router;
