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
import { feedSyncQueue, cveEnrichmentQueue, maintenanceQueue, neo4jSyncQueue, sandboxPollerQueue, brandMonitorQueue } from './index';
import { createLogger } from '../lib/logger';
import { injectTraceContext } from './tracing';
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
        // PRIMARY CVE ingest. cvelistV5 delta.json refreshes every ~7
        // minutes; we poll every 15. New CVEs typically reach our DB
        // within 15 min of CNA disclosure. NVD often takes 5-14 days
        // to surface the same CVE, so we keep NVD around only as a
        // CVSS-score fallback (the work-driven enrichment trigger fires
        // OSV first, NVD second, for any row with NULL cvss_score).
        key: 'cveOrgSync',
        jobId: 'scheduled-cveorg-sync',
        name: 'cveorg-sync',
        description: 'Sync CVE.org cvelistV5 (CNA-published CVEs, near-real-time)',
        defaultCron: '*/15 * * * *',
        queue: feedSyncQueue,
        payload: { source: 'cveorg' },
    },
    {
        key: 'nvdSync',
        jobId: 'scheduled-nvd-sync',
        name: 'nvd-sync',
        description: 'Sync NIST NVD CVE database (CVSS backfill for older CVEs)',
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
    {
        // AI Incident Database (incidentdatabase.ai). The live AI-threat
        // landscape signal — real-world AI harm/failure incidents. Paged from
        // the GraphQL API (~8 small requests for the ~1.5k corpus), so daily
        // at 02:15 UTC is cheap. Idempotent upsert on incident_id.
        key: 'aiidSync',
        jobId: 'scheduled-aiid-sync',
        name: 'aiid-sync',
        description: 'Sync AI Incident Database (incidentdatabase.ai) incidents',
        defaultCron: '15 2 * * *',
        queue: feedSyncQueue,
        payload: { source: 'aiid' },
    },
    {
        // OFAC SDN sanctioned crypto addresses (US Treasury). The free,
        // authoritative on-chain attribution feed — dual-sinks to iocs
        // (tag `sanctioned`, drives Landscape shift) + wallets. OFAC only
        // republishes on a designation action (days–weeks apart), so daily
        // at 03:00 UTC is ample; the upsert is idempotent.
        key: 'ofacSync',
        jobId: 'scheduled-ofac-sync',
        name: 'ofac-sync',
        description: 'Sync OFAC SDN sanctioned cryptocurrency addresses',
        defaultCron: '0 3 * * *',
        queue: feedSyncQueue,
        payload: { source: 'ofac' },
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
    {
        key: 'epssSync',
        jobId: 'scheduled-epss-sync',
        name: 'epss-sync',
        description: 'Sync EPSS exploit-prediction scores from FIRST.org',
        // 06:00 UTC daily — gives FIRST.org's nightly publish window time
        // to finish (they update ~00:00 UTC) and lands well after our
        // CISA-KEV / NVD syncs so the freshest set of CVEs gets scored.
        defaultCron: '0 6 * * *',
        queue: feedSyncQueue,
        payload: { source: 'epss' },
    },

    // Phase 5 #3 — HIBP breach catalog. Daily at 06:30 UTC, 30 minutes
    // after EPSS. The /breaches endpoint refresh cadence is on the order
    // of days; once a day is more than sufficient and stays well under
    // any reasonable rate limit. Free-tier only — no /breachedaccount.
    {
        key: 'hibpSync',
        jobId: 'scheduled-hibp-sync',
        name: 'hibp-sync',
        description: 'Sync HIBP breach catalog (free-tier /breaches endpoint)',
        defaultCron: '30 6 * * *',
        queue: feedSyncQueue,
        payload: { source: 'hibp' },
    },

    // --- Graph sync ----------------------------------------------------
    {
        key: 'neo4jFullSync',
        jobId: 'scheduled-neo4j-full-sync',
        name: 'neo4j-sync-full',
        description: 'Full Postgres → Neo4j graph rebuild (actors, techniques, malware, tools, relationships, pulses + IOCs, CVEs, similarity)',
        // 07:30 UTC daily — lands after the 06:00 EPSS sync finishes and
        // before the day's first analyst surfaces. The orchestrator runs
        // ~8 minutes on prod-scale data (74k nodes / 30k edges in the
        // 2026-06-05 backfill); a daily cadence keeps the graph fresh
        // without burning Neo4j into a write loop.
        //
        // Without this scheduled rebuild Neo4j drifts: the initial
        // populate is manual via /admin/jobs/neo4j-sync, and Postgres
        // grew from 37k → 249k IOCs without the graph ever catching up.
        // Discovered 2026-06-05 when /graph?q=... returned 0 nodes for
        // IOCs that were definitely in Postgres.
        defaultCron: '30 7 * * *',
        queue: neo4jSyncQueue,
        payload: { syncType: 'full' },
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

    // Always-on hygiene — drop OpenSearch documents for IOCs the
    // confidenceDecay job has marked decayed (iocs.decayed_at IS NOT NULL).
    // Cron sits one hour after confidenceDecay (01:00 UTC) so the marker
    // stamping is settled by the time the prune queries — guarantees a
    // single decay-tick → prune-tick flow per day instead of racing them.
    {
        key: 'opensearchPrune',
        jobId: 'scheduled-opensearch-prune',
        name: 'opensearch-prune',
        description: 'Drop OpenSearch docs for IOCs marked decayed by the decay job',
        defaultCron: '0 2 * * *',
        queue: maintenanceQueue,
        payload: { type: 'opensearch-prune' },
    },
    // One-shot backfill that keeps the scoring engine honest on rows
    // ingested before the stream-consumer scoring hook (or by feed-sync
    // upserts that don't go through the stream). Schedule is weekly
    // safety-net cadence — Sundays 02:30 UTC, between opensearchPrune
    // (02:00) and the weekly data-retention job (03:30). The
    // `onlyUnscored: true` filter makes steady-state runs no-ops once
    // every row has a non-zero score, so the weekly cron is essentially
    // a backstop. Operators run it ad-hoc via Admin -> Schedules ->
    // riskScoreBackfill -> Run now for the first full-corpus sweep.
    {
        key: 'riskScoreBackfill',
        jobId: 'scheduled-risk-score-backfill',
        name: 'risk-score-backfill',
        description: 'Score IOCs whose risk_score is 0 (backfill for pre-streamConsumer rows)',
        defaultCron: '30 2 * * 0',
        queue: maintenanceQueue,
        payload: { type: 'risk-score-backfill' },
    },

    // Phase 4 #5b — sandbox poll. Every 5 minutes is a reasonable cadence
    // for ANY.RUN's typical analysis duration (1-3 min). Joe Sandbox and
    // Hybrid Analysis run longer; the per-row 1-day TTL caps how long
    // we keep checking before giving up.
    {
        key: 'sandboxPoll',
        jobId: 'scheduled-sandbox-poll',
        name: 'sandbox-poll',
        description: 'Refresh non-terminal sandbox_reports against their vendors',
        defaultCron: '*/5 * * * *',
        queue: sandboxPollerQueue,
        payload: { type: 'sandbox-poll' },
    },

    // Phase 5 #1 — brand monitor sweep. Every 6 hours is a sensible
    // default — typo-squat registrations don't churn faster than that,
    // and a full sweep is bounded but not free (one DNS lookup per
    // permutation per apex; ~1k permutations per 12-char label).
    // Operators can re-tune via the override UI or trigger ad-hoc
    // sweeps via POST /v1/brand/sweep.
    {
        key: 'brandMonitorSweep',
        jobId: 'scheduled-brand-monitor-sweep',
        name: 'brand-sweep',
        description: 'Sweep monitored apexes for typo-squat permutations',
        defaultCron: '0 */6 * * *',
        queue: brandMonitorQueue,
        payload: { type: 'brand-sweep' },
    },

    // Phase 5 #2 — threat-actor TTP changelog differ. 04:30 UTC sits
    // 30 minutes after the weekly MITRE sync (Sunday 04:00) so the
    // first weekly diff has the freshest data, and the daily runs
    // catch any out-of-band MITRE updates that landed via the manual
    // import path.
    {
        key: 'mitreTtpDiff',
        jobId: 'scheduled-mitre-ttp-diff',
        name: 'mitre-ttp-diff',
        description: 'Diff actor → technique attributions vs prior snapshot',
        defaultCron: '30 4 * * *',
        queue: maintenanceQueue,
        payload: { type: 'mitre-ttp-diff' },
    },

    // Phase 5 #4 — dark-web Ahmia scan. Daily 07:00 UTC, 30 min after
    // HIBP. Ahmia is rate-friendly + the platform queries clearnet only,
    // so once-a-day is plenty.
    {
        key: 'darkWebAhmiaScan',
        jobId: 'scheduled-dark-web-ahmia-scan',
        name: 'dark-web-ahmia-scan',
        description: 'Query Ahmia for every enabled dark_web_watchterms entry',
        defaultCron: '0 7 * * *',
        queue: maintenanceQueue,
        payload: { type: 'dark-web-ahmia-scan' },
    },

    // Phase 5 #5 — paste-site monitoring (GitHub Gist firehose).
    // Every 30 minutes — gists churn fast; longer windows risk missing
    // an embed before the author deletes it. ~90 gists scanned per run.
    {
        key: 'pasteGistScan',
        jobId: 'scheduled-paste-gist-scan',
        name: 'paste-gist-scan',
        description: 'Match operator watchterms against the GitHub Gist firehose',
        defaultCron: '*/30 * * * *',
        queue: maintenanceQueue,
        payload: { type: 'paste-gist-scan' },
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
 * Remove every existing repeatable registration matching this job's BullMQ
 * `name`. We match by `name`, not by `id` — `getRepeatableJobs()` returns
 * `id: undefined` in current BullMQ versions, which silently breaks any
 * jobId-based dedup and was leaving zombies behind on every override change.
 *
 * Using `name` (e.g. `nvd-sync`) means a registry entry with that name is
 * the single owner: at reconcile time, every prior schedule for that name
 * is dropped before the new one is added. A registry rename is the only
 * thing that would orphan an old schedule under this rule, and
 * `cleanupUnregisteredRepeatables()` handles that case.
 */
async function removeRepeatableFor(reg: ScheduledJobRegistration): Promise<void> {
    const existing = await reg.queue.getRepeatableJobs();
    for (const r of existing) {
        if (r.name === reg.name) {
            await reg.queue.removeRepeatableByKey(r.key);
        }
    }
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
 * Remove repeatable jobs from Redis that aren't in `JOB_REGISTRY`.
 *
 * Two failure modes this catches:
 *
 *   1. Registry rename — old `name` lingers in Redis after a code change.
 *      Identified by: a repeatable's `name` isn't claimed by any registry
 *      entry. Drop it.
 *
 *   2. Duplicate registration — a single registry `name` has multiple
 *      schedules in Redis (e.g. a pattern was changed but the old schedule
 *      survived because the previous version of `removeRepeatableFor` used
 *      `r.id` which BullMQ returns as undefined). Identified by: more than
 *      one repeatable with the same `name`. Keep the one matching the
 *      current registry pattern and drop the rest.
 *
 * Matches on `name`, not `id`, because `getRepeatableJobs()` returns
 * `id: undefined` in current BullMQ versions — every prior id-based check
 * was silently a no-op and that's exactly how the zombies built up.
 */
async function cleanupUnregisteredRepeatables(): Promise<string[]> {
    // name → desired pattern (resolved per current overrides)
    const desired = new Map<string, string>();
    for (const reg of JOB_REGISTRY) {
        const config = await resolveJobConfig(reg);
        if (config) desired.set(reg.name, config.cron);
    }

    const managedQueues = [feedSyncQueue, maintenanceQueue, cveEnrichmentQueue, sandboxPollerQueue, brandMonitorQueue];
    const removed: string[] = [];

    for (const queue of managedQueues) {
        const repeatables = await queue.getRepeatableJobs();
        for (const r of repeatables) {
            const name = r.name;
            if (!name) continue;
            const desiredPattern = desired.get(name);
            // Case 1: name unknown to current registry → orphan, drop.
            // Case 2: name known but pattern doesn't match what reconcile
            //         just registered → it's the loser of a registration
            //         race, drop.
            if (desiredPattern && r.pattern === desiredPattern) continue;
            try {
                await queue.removeRepeatableByKey(r.key);
                removed.push(`${queue.name}/${name}/${r.pattern}`);
                log.info('Removed stale repeatable', {
                    queue: queue.name, name, pattern: r.pattern, key: r.key,
                    reason: desiredPattern ? 'pattern-mismatch' : 'name-not-in-registry',
                });
            } catch (err) {
                log.warn('Could not remove stale repeatable', {
                    queue: queue.name, name, error: (err as Error).message,
                });
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
    const [feedSyncJobs, maintenanceJobs, sandboxPollerJobs] = await Promise.all([
        feedSyncQueue.getRepeatableJobs(),
        maintenanceQueue.getRepeatableJobs(),
        sandboxPollerQueue.getRepeatableJobs(),
    ]);

    return {
        feedSync: feedSyncJobs,
        maintenance: maintenanceJobs,
        sandboxPolling: sandboxPollerJobs,
    };
}

/** Remove all scheduled jobs across managed queues. */
export async function clearScheduledJobs(): Promise<void> {
    log.info('Clearing all scheduled jobs');
    const queues = [feedSyncQueue, maintenanceQueue, cveEnrichmentQueue, sandboxPollerQueue, brandMonitorQueue];
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
    // Use the canonical job name so the worker's switch(job.name) dispatcher
    // routes to the correct handler. BullMQ auto-generates a unique jobId,
    // so there's no collision with the scheduled cron entry that lives under
    // the same name.
    //
    // injectTraceContext lifts the current HTTP-handler span into the job
    // data so the consumer in retentionWorker / brandMonitorWorker / etc.
    // can resume the same trace; without it the worker's DB spans become
    // orphans that don't link back to the operator's "Run now" click.
    const job = await reg.queue.add(reg.name, injectTraceContext(reg.payload), { priority: 1 });
    log.info('Triggered ad-hoc run for scheduled job', { key, jobId: job.id });
    return { jobId: job.id, queue: reg.queue.name };
}

/** Legacy convenience for arbitrary "sync all" / "sync OTX" triggers. */
export async function triggerImmediateSync(source: 'otx' | 'cisa' | 'nvd' | 'all' = 'all') {
    const job = await feedSyncQueue.add(
        `immediate-${source}-sync`,
        injectTraceContext({ source, options: { limit: 100 } }),
        { priority: 1 },
    );
    log.info('Triggered immediate sync', { source, jobId: job.id });
    return job;
}
