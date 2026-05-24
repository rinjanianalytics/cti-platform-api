/**
 * Admin Feeds Management
 *
 *   GET /admin/feeds                      — list every feed + schedule + last-run summary
 *   GET /admin/feeds/:feedId/history      — last N runs from feed_sync_runs
 *
 * Everything else (enable/disable, interval, run-now) reuses the schedules
 * endpoints — feeds *are* scheduled jobs, so this layer is a feed-centric
 * view over the schedule registry plus the feed_sync_runs history table.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { getScheduledJobsAdminView } from '../../queues/scheduler';
import { getFeedSyncHistory } from '../../services/configStore';

const router = new Hono();

/**
 * Maps the camelCase JOB_REGISTRY key → the `feed_sync_runs.feed_id`
 * value the worker writes when it records a run. Feeds in the registry
 * not listed here aren't recorded against the history table (intentional
 * — non-feed schedules like confidenceDecay don't belong).
 */
const FEED_REGISTRY_TO_SOURCE: Record<string, string> = {
    otxSync:            'otx',
    cisaSync:           'cisa',
    nvdSync:            'nvd',
    abusesslSync:       'abusessl',
    threatfoxSync:      'threatfox',
    urlhausSync:        'urlhaus',
    malwarebazaarSync:  'malwarebazaar',
    openphishSync:      'openphish',
    mitreSync:          'mitre',
    mispGalaxySync:     'mispgalaxy',
};

/** GET /admin/feeds — feed-centric view (every entry that has a feed_sync_runs source). */
router.get('/feeds', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    const allSchedules = await getScheduledJobsAdminView();
    const feedKeys = Object.keys(FEED_REGISTRY_TO_SOURCE);
    const feedSchedules = allSchedules.filter(s => feedKeys.includes(s.key));

    // Fetch the most recent run for each feed in parallel — single SELECT
    // per feed; index on (feed_id, started_at DESC) keeps this fast.
    const feeds = await Promise.all(feedSchedules.map(async (s) => {
        const source = FEED_REGISTRY_TO_SOURCE[s.key];
        const recent = await getFeedSyncHistory(source, 1).catch(() => []);
        const last = recent[0] ?? null;
        return {
            key: s.key,
            source,
            name: s.name,
            description: s.description,
            defaultCron: s.defaultCron,
            effectiveCron: s.effectiveCron,
            enabled: s.enabled,
            override: s.override,
            lastRun: last && {
                status: last.status,
                startedAt: last.startedAt,
                completedAt: last.completedAt,
                durationMs: last.durationMs,
                itemsIngested: last.itemsIngested,
                errors: last.errors,
                errorDetails: last.errorDetails,
                triggeredBy: last.triggeredBy,
            },
        };
    }));

    return c.json({
        success: true,
        data: { feeds, count: feeds.length },
    });
});

/** GET /admin/feeds/:feedId/history — newest-first run history. */
router.get('/feeds/:feedId/history', requireAuth, requireRole('admin', 'auditor'), async (c) => {
    const feedId = c.req.param('feedId');
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 20, 1), 200);
    const runs = await getFeedSyncHistory(feedId, limit);
    return c.json({ success: true, data: { feedId, runs, count: runs.length } });
});

export default router;
