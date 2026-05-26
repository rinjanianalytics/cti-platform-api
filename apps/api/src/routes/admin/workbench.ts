/**
 * Workbench — third-party BullMQ dashboard mounted under /admin/workbench.
 *
 * Workbench (https://getworkbench.dev) is a drop-in dashboard for BullMQ
 * with a flow/DAG view, metrics, and per-job search. It complements our
 * own /admin/queues page rather than replacing it — that page handles
 * the operational basics (pause / resume / drain / retry-all / clean),
 * while Workbench is the deep-dive tool for niche debugging.
 *
 * Auth model:
 *   Workbench only supports HTTP Basic out of the box, but having a
 *   second password for an embedded tool is poor UX. Instead, we gate
 *   the mount with our own `requireAuth + requireRole('admin')` and let
 *   Workbench run with no auth of its own. This works because:
 *     1. The dashboard mirrors its localStorage JWT into a `rinjani_token`
 *        cookie on its own origin (see dashboard `setToken`).
 *     2. The Next.js rewrite for /admin/workbench/* is same-origin from
 *        the browser's perspective, so the cookie auto-attaches to every
 *        request — including Workbench's own internal fetches.
 *     3. The cookie reaches our API via the rewrite's forwarded headers,
 *        where `optionalAuth` parses it and resolves the user.
 *     4. `requireAuth + requireRole('admin')` then rejects anyone who
 *        isn't a logged-in admin before Workbench's handlers run.
 *
 * Net effect: visiting /admin/workbench when you're logged in to the
 * dashboard just works. Visiting it logged out returns 401 without
 * ever reaching Workbench.
 */

import { Hono } from 'hono';
import { WorkbenchCore, buildWorkbenchApp } from '@rinjani/workbench-core';
import { allQueues } from '../../queues/stats';
import { requireAuth, requireRole } from '../../middleware/auth';
import {
    JOB_REGISTRY,
    reconcileScheduledJobByKey,
    triggerScheduledJobNow,
} from '../../queues/scheduler';
import {
    upsertOverride,
    INTERVAL_PRESETS,
    isIntervalPreset,
} from '../../services/scheduledJobOverrides';

const router = new Hono();

/**
 * Map a BullMQ repeatable's `name` (e.g. `otx-sync`) to the JOB_REGISTRY
 * `key` (e.g. `otxSync`). Workbench's scheduler list returns the BullMQ
 * name; our override + reconcile layer is keyed by JOB_REGISTRY.key. The
 * mapping is just registry lookup — no fuzzy matching to avoid silently
 * routing to the wrong job.
 */
function jobNameToRegistryKey(jobName: string): string {
    const entry = JOB_REGISTRY.find(r => r.name === jobName);
    if (!entry) {
        throw new Error(`Unknown scheduled job name: ${jobName} (not in JOB_REGISTRY)`);
    }
    return entry.key;
}

// Workbench takes over the whole viewport (it ships X-Frame-Options that
// blocks framing on most builds), so we don't try to iframe it inside our
// admin chrome. Sidebar link does a plain navigation; browser back returns
// to the dashboard.
//
// We vendored `@getworkbench/core` into `packages/workbench-core/` so we can
// add scheduler CRUD on top of upstream's read-only view. The 37-line
// `@getworkbench/hono` adapter is inlined here instead of being kept as a
// separate workspace package. See `packages/workbench-core/VENDOR.md`.
//
// Scheduler edits are routed through `scheduledJobOverrides` + `reconcileScheduledJobByKey`
// rather than mutating BullMQ directly — `setupScheduledJobs` runs on every
// API boot and would clobber direct edits. The same backend powers our native
// `/admin/schedules` page, so both UIs stay consistent.
router.use('/workbench/*', requireAuth, requireRole('admin'));
router.route(
    '/workbench',
    buildWorkbenchApp(new WorkbenchCore({
        queues: allQueues,
        // No basic auth — gated by our middleware above.
        title: 'Workbench · Rinjani',
        basePath: '/admin/workbench',
        readonly: process.env.WORKBENCH_READONLY === 'true',
        // Surface common fields from BullMQ job.data as filterable tags.
        tags: ['source', 'feedId', 'iocId', 'cveId'],
        schedulerActions: {
            intervalPresets: Object.entries(INTERVAL_PRESETS).map(([value, cron]) => ({
                value,
                label: ({
                    '15m':    'Every 15 minutes',
                    '30m':    'Every 30 minutes',
                    '1h':     'Every hour',
                    '4h':     'Every 4 hours',
                    '6h':     'Every 6 hours',
                    'daily':  'Daily · 02:00',
                    'weekly': 'Weekly · Sunday 04:00',
                } as Record<string, string>)[value] ?? value,
                cron,
            })),
            onEdit: async ({ jobName, intervalPreset, enabled }) => {
                const key = jobNameToRegistryKey(jobName);
                const preset = intervalPreset !== undefined
                    ? (intervalPreset === null ? null : (isIntervalPreset(intervalPreset) ? intervalPreset : null))
                    : undefined;
                await upsertOverride(key, {
                    enabled,
                    intervalPreset: preset,
                }, null);
                const result = await reconcileScheduledJobByKey(key);
                return {
                    status: result.status,
                    cron: result.cron,
                };
            },
            onRemove: async ({ jobName }) => {
                const key = jobNameToRegistryKey(jobName);
                await upsertOverride(key, { enabled: false }, null);
                await reconcileScheduledJobByKey(key);
                return { status: 'disabled' };
            },
            onRunNow: async ({ jobName }) => {
                const key = jobNameToRegistryKey(jobName);
                const result = await triggerScheduledJobNow(key);
                return { jobId: result.jobId ?? '' };
            },
        },
    })),
);

export default router;
