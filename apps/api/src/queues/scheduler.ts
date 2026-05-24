/**
 * BullMQ Scheduled Jobs
 *
 * Configures repeatable jobs for periodic feed syncs and maintenance tasks.
 *
 * Each scheduled job is described in JOB_REGISTRY with:
 *   - key:         stable identifier (DB primary key in scheduled_job_overrides)
 *   - jobId:       deterministic BullMQ jobId so repeatable jobs are
 *                  idempotent on restart
 *   - name:        BullMQ job name (used by workers' .add())
 *   - description: surfaced in the admin UI
 *   - defaultCron: shipped default; overridden by admin via interval preset
 *   - queue:       the Queue this job runs on
 *   - payload:     job data
 *
 * `setupScheduledJobs()` reads admin overrides at boot and registers jobs
 * accordingly. `reconcileScheduledJob()` is called from the admin endpoint
 * after an override changes — both the API process and the worker process
 * see the same Redis state, so no cross-process messaging is needed.
 */

import type { Queue } from 'bullmq';
import { feedSyncQueue, cveEnrichmentQueue, maintenanceQueue } from './index';
import { createLogger } from '../lib/logger';
import {
    getOverride,
    listOverrides,
    presetToCron,
    type IntervalPreset,
} from '../services/scheduledJobOverrides';

const log = createLogger('Scheduler');

// ============================================================================
// Job Registry — single source of truth for every scheduled job
// ============================================================================

export interface ScheduledJobRegistration {
    /** Stable key (PK in scheduled_job_overrides). */
    key: string;
    /** Deterministic BullMQ jobId so restarts don't duplicate the schedule. */
    jobId: string;
    /** BullMQ job name. */
    name: string;
    description: string;
    /** Cron pattern shipped as the default; admins can override via preset. */
    defaultCron: string;
    queue: Queue;
    payload: Record<string, unknown>;
}

export const JOB_REGISTRY: ScheduledJobRegistration[] = [
    // --- High-frequency feed syncs --------------------------------------
    {
        key: 'otxSync',
        jobId: 'scheduled-otx-sync',
        name: 'otx-sync',
        description: 'Sync AlienVault OTX pulses',
        defaultCron: '*/15 * * * *',
        queue: feedSyncQueue,
        payload: { source: 'otx', options: { limit: 50 } },
    },
    {
        key: 'cisaSync',
        jobId: 'scheduled-cisa-sync',
        name: 'cisa-sync',
        description: 'Sync CISA Known Exploited Vulnerabilities',
        defaultCron: '0 * * * *',
        queue: feedSyncQueue,
        payload: { source: 'cisa' },
    },
    {
        key: 'nvdSync',
        jobId: 'scheduled-nvd-sync',
        name: 'nvd-sync',
        description: 'Sync NIST NVD CVE database (recently modified)',
        defaultCron: '0 2 * * *',
        queue: feedSyncQueue,
        payload: { source: 'nvd', options: { limit: 100 } },
    },

    // --- CVE enrichment -------------------------------------------------
    // INTENTIONALLY NOT IN THE REGISTRY.
    // CVE enrichment is now work-driven: a Postgres trigger fires NOTIFY
    // 'rinjani_work' whenever a vulnerability row lands with NULL CVSS,
    // and `services/workListener.ts` enqueues an enrichment batch (with
    // Redis dedup so a bulk feed sync collapses to a single wake-up).
    // A backstop sweep runs at worker boot. See migration 0033.

    // --- IOC feeds (abuse.ch ecosystem + OpenPhish) --------------------
    {
        key: 'abusesslSync',
        jobId: 'scheduled-abusessl-sync',
        name: 'abusessl-sync',
        description: 'Sync Abuse.ch SSL blacklist',
        defaultCron: '30 */6 * * *',
        queue: feedSyncQueue,
        payload: { source: 'abusessl' },
    },
    {
        key: 'threatfoxSync',
        jobId: 'scheduled-threatfox-sync',
        name: 'threatfox-sync',
        description: 'Sync ThreatFox IOCs',
        defaultCron: '0 */6 * * *',
        queue: feedSyncQueue,
        payload: { source: 'threatfox' },
    },
    {
        key: 'urlhausSync',
        jobId: 'scheduled-urlhaus-sync',
        name: 'urlhaus-sync',
        description: 'Sync URLhaus malicious URLs',
        defaultCron: '15 */6 * * *',
        queue: feedSyncQueue,
        payload: { source: 'urlhaus' },
    },
    {
        key: 'malwarebazaarSync',
        jobId: 'scheduled-malwarebazaar-sync',
        name: 'malwarebazaar-sync',
        description: 'Sync MalwareBazaar hashes',
        defaultCron: '45 */6 * * *',
        queue: feedSyncQueue,
        payload: { source: 'malwarebazaar' },
    },
    {
        key: 'openphishSync',
        jobId: 'scheduled-openphish-sync',
        name: 'openphish-sync',
        description: 'Sync OpenPhish phishing URLs',
        defaultCron: '0 */4 * * *',
        queue: feedSyncQueue,
        payload: { source: 'openphish' },
    },

    // --- Knowledge base syncs ------------------------------------------
    {
        key: 'mitreSync',
        jobId: 'scheduled-mitre-sync',
        name: 'mitre-sync',
        description: 'Sync MITRE ATT&CK framework',
        defaultCron: '0 4 * * 0',
        queue: feedSyncQueue,
        payload: { source: 'mitre' },
    },
    {
        key: 'mispGalaxySync',
        jobId: 'scheduled-mispgalaxy-sync',
        name: 'mispgalaxy-sync',
        description: 'Sync MISP Galaxy threat-actor enrichment',
        defaultCron: '0 5 * * *',
        queue: feedSyncQueue,
        payload: { source: 'mispgalaxy' },
    },

    // --- Maintenance ---------------------------------------------------
    {
        key: 'confidenceDecay',
        jobId: 'scheduled-confidence-decay',
        name: 'confidence-decay',
        description: 'Apply exponential decay to IOC confidence scores',
        defaultCron: '0 1 * * *',
        queue: maintenanceQueue,
        payload: { type: 'confidence-decay' },
    },
    {
        key: 'dataRetention',
        jobId: 'scheduled-data-retention',
        name: 'data-retention',
        description: 'Prune old audit logs, resolved alerts, archive stale IOCs',
        defaultCron: '30 3 * * 0',
        queue: maintenanceQueue,
        payload: { type: 'data-retention' },
    },
];

// ============================================================================
// Public API
// ============================================================================

/**
 * Resolve the cron pattern for a job, taking the admin override into account.
 * Returns null if the admin has disabled the job — the caller should skip it.
 */
async function resolveJobConfig(reg: ScheduledJobRegistration): Promise<
    { cron: string; payload: Record<string, unknown> } | null
> {
    const override = await getOverride(reg.key);
    if (override && !override.enabled) return null;

    const cron = presetToCron(override?.intervalPreset) ?? reg.defaultCron;
    const payload = override?.payload ? { ...reg.payload, ...override.payload } : reg.payload;
    return { cron, payload };
}

/**
 * Remove the existing repeatable registration for a job, if any. Looks up by
 * jobId rather than pattern so it works across pattern changes.
 */
async function removeRepeatableFor(reg: ScheduledJobRegistration): Promise<void> {
    const existing = await reg.queue.getRepeatableJobs();
    const match = existing.find(r => r.id === reg.jobId);
    if (match) await reg.queue.removeRepeatableByKey(match.key);
}

/**
 * Register (or re-register) a single scheduled job based on current overrides.
 * Safe to call repeatedly — removes any prior registration first.
 *
 * Called at boot from setupScheduledJobs(), and from the admin endpoint
 * after an override is saved.
 */
export async function reconcileScheduledJob(reg: ScheduledJobRegistration): Promise<{
    key: string; status: 'enabled' | 'disabled'; cron?: string;
}> {
    await removeRepeatableFor(reg);

    const config = await resolveJobConfig(reg);
    if (!config) {
        log.info('Scheduled job disabled by override', { key: reg.key });
        return { key: reg.key, status: 'disabled' };
    }

    await reg.queue.add(reg.name, config.payload, {
        repeat: { pattern: config.cron },
        jobId: reg.jobId,
    });
    log.info('Scheduled job registered', {
        key: reg.key,
        cron: config.cron,
        description: reg.description,
    });
    return { key: reg.key, status: 'enabled', cron: config.cron };
}

/** Reconcile a job by key. Throws if the key isn't in the registry. */
export async function reconcileScheduledJobByKey(key: string) {
    const reg = JOB_REGISTRY.find(r => r.key === key);
    if (!reg) throw new Error(`Unknown scheduled job key: ${key}`);
    return reconcileScheduledJob(reg);
}

/**
 * Remove repeatable jobs from Redis that are no longer in `JOB_REGISTRY`.
 *
 * Without this, removing an entry from the registry (e.g. when we migrated
 * CVE enrichment from cron to NOTIFY-driven in slice 6) leaves a zombie:
 * BullMQ keeps generating delayed instances on the old schedule because
 * the repeatable still lives in Redis. This pass deletes any repeatable
 * whose jobId isn't in the current registry, restoring the registry as
 * the single source of truth for "what's actually scheduled".
 */
async function cleanupUnregisteredRepeatables(): Promise<string[]> {
    const knownJobIds = new Set(JOB_REGISTRY.map(r => r.jobId));
    // Every queue we've ever scheduled work on. Adding a new queue to the
    // registry above should also be added here.
    const managedQueues = [feedSyncQueue, maintenanceQueue, cveEnrichmentQueue];
    const removed: string[] = [];

    for (const queue of managedQueues) {
        const repeatables = await queue.getRepeatableJobs();
        for (const r of repeatables) {
            if (r.id && !knownJobIds.has(r.id)) {
                try {
                    await queue.removeRepeatableByKey(r.key);
                    removed.push(`${queue.name}/${r.id}`);
                    log.info('Removed stale repeatable', { queue: queue.name, jobId: r.id, key: r.key });
                } catch (err) {
                    log.warn('Could not remove stale repeatable', {
                        queue: queue.name, jobId: r.id, error: (err as Error).message,
                    });
                }
            }
        }
    }
    return removed;
}

/** Setup all scheduled jobs at boot. */
export async function setupScheduledJobs(): Promise<void> {
    log.info('Setting up scheduled jobs', { count: JOB_REGISTRY.length });
    try {
        for (const reg of JOB_REGISTRY) {
            await reconcileScheduledJob(reg);
        }
        const removed = await cleanupUnregisteredRepeatables();
        if (removed.length > 0) {
            log.info('Cleaned up stale repeatables', { count: removed.length, removed });
        }
        log.info('All scheduled jobs configured');
    } catch (err) {
        log.error('Failed to setup scheduled jobs', err as Error);
    }
}

/**
 * Admin-view of every scheduled job — registry entry + current override (if
 * any) + the effective cron that's actually running.
 */
export async function getScheduledJobsAdminView() {
    const overrides = await listOverrides();
    const byKey = new Map(overrides.map(o => [o.jobKey, o]));

    return JOB_REGISTRY.map(reg => {
        const override = byKey.get(reg.key) ?? null;
        const effectiveCron = override && !override.enabled
            ? null
            : presetToCron(override?.intervalPreset) ?? reg.defaultCron;

        return {
            key: reg.key,
            jobId: reg.jobId,
            name: reg.name,
            description: reg.description,
            defaultCron: reg.defaultCron,
            queueName: reg.queue.name,
            payload: reg.payload,
            override: override ? {
                enabled: override.enabled,
                intervalPreset: override.intervalPreset as IntervalPreset | null,
                payload: override.payload,
                updatedAt: override.updatedAt.toISOString(),
                updatedBy: override.updatedBy,
            } : null,
            enabled: override?.enabled ?? true,
            effectiveCron,
        };
    });
}

/** Get all repeatable jobs across the queues we manage. */
export async function getScheduledJobs() {
    const [feedSyncJobs, maintenanceJobs] = await Promise.all([
        feedSyncQueue.getRepeatableJobs(),
        maintenanceQueue.getRepeatableJobs(),
    ]);

    return {
        feedSync: feedSyncJobs,
        maintenance: maintenanceJobs,
    };
}

/** Remove all scheduled jobs across managed queues. */
export async function clearScheduledJobs(): Promise<void> {
    log.info('Clearing all scheduled jobs');
    const queues = [feedSyncQueue, maintenanceQueue, cveEnrichmentQueue];
    for (const q of queues) {
        const jobs = await q.getRepeatableJobs();
        for (const job of jobs) {
            await q.removeRepeatableByKey(job.key);
        }
    }
    log.info('All scheduled jobs cleared');
}

/** Trigger an immediate one-off run for a registered job, bypassing the cron. */
export async function triggerScheduledJobNow(key: string) {
    const reg = JOB_REGISTRY.find(r => r.key === key);
    if (!reg) throw new Error(`Unknown scheduled job key: ${key}`);
    const job = await reg.queue.add(`adhoc-${reg.name}-${Date.now()}`, reg.payload, {
        priority: 1,
    });
    log.info('Triggered ad-hoc run for scheduled job', { key, jobId: job.id });
    return { jobId: job.id, queue: reg.queue.name };
}

/** Legacy convenience for arbitrary "sync all" / "sync OTX" triggers. */
export async function triggerImmediateSync(source: 'otx' | 'cisa' | 'nvd' | 'all' = 'all') {
    const job = await feedSyncQueue.add(
        `immediate-${source}-sync`,
        { source, options: { limit: 100 } },
        { priority: 1 },
    );
    log.info('Triggered immediate sync', { source, jobId: job.id });
    return job;
}
