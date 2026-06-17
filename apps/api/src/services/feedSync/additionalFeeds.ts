/**
 * Additional Feed Sync Wrappers
 *
 * Wraps worker feed scripts for use by the API-side BullMQ feedSyncWorker.
 * Uses dynamic imports with @ts-ignore since worker scripts are outside
 * the API tsconfig rootDir — they resolve fine at runtime (tsx).
 */

import type { SyncResult } from './types';

function normalise(
    src: { processed: number; failed: number; errors: string[] },
): SyncResult {
    return {
        success: src.failed === 0 || src.processed > 0,
        pulsesProcessed: 1,
        indicatorsProcessed: src.processed + src.failed,
        indicatorsAdded: src.processed,
        indicatorsUpdated: 0,
        errors: src.errors,
    };
}

function emptyResult(success: boolean, errors: string[] = []): SyncResult {
    return {
        success,
        pulsesProcessed: success ? 1 : 0,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors,
    };
}

export async function syncAbuseSSLFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncAbuseSSL } = await import('../../../../worker/src/feeds/abusessl');
    return normalise(await syncAbuseSSL());
}

export async function syncThreatFoxFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncThreatFox } = await import('../../../../worker/src/feeds/threatfox');
    return normalise(await syncThreatFox());
}

export async function syncURLhausFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncURLhaus } = await import('../../../../worker/src/feeds/urlhaus');
    return normalise(await syncURLhaus());
}

export async function syncMalwareBazaarFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncMalwareBazaar } = await import('../../../../worker/src/feeds/malwarebazaar');
    return normalise(await syncMalwareBazaar());
}

export async function syncOpenPhishFeed(): Promise<SyncResult> {
    // @ts-ignore
    const { syncOpenPhish } = await import('../../../../worker/src/feeds/openphish');
    return normalise(await syncOpenPhish());
}

export async function syncOFACFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncOFAC } = await import('../../../../worker/src/feeds/ofac');
    return normalise(await syncOFAC());
}

export async function syncAIIncidentsFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncAIIncidents } = await import('../../../../worker/src/feeds/ai-incidents');
    return normalise(await syncAIIncidents());
}

export async function syncScamSnifferFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncScamSniffer } = await import('../../../../worker/src/feeds/scamsniffer');
    return normalise(await syncScamSniffer());
}

export async function syncDefiLlamaFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncDefiLlama } = await import('../../../../worker/src/feeds/defillama');
    return normalise(await syncDefiLlama());
}

export async function syncMITREFeed(): Promise<SyncResult> {
    try {
        // @ts-ignore
        const { syncMitreAttack } = await import('../../../../worker/src/feeds/mitre');
        const r = await syncMitreAttack() as
            | { actors?: number; techniques?: number; tactics?: number; malware?: number; tools?: number; relationships?: number }
            | undefined;
        // MITRE writes to half a dozen tables (threat_actors + techniques +
        // tactics + malware + tools + relationships) per sync. Sum the
        // per-table counts so feed_sync_runs.items_ingested reflects
        // actual rows written (footgun #15) instead of always 0.
        const total = r
            ? (r.actors ?? 0) + (r.techniques ?? 0) + (r.tactics ?? 0) + (r.malware ?? 0) + (r.tools ?? 0) + (r.relationships ?? 0)
            : 0;
        return { ...emptyResult(true), totalRowsAffected: total };
    } catch (err) {
        return emptyResult(false, [(err as Error).message]);
    }
}

export async function syncMISPGalaxyFeed(): Promise<SyncResult> {
    try {
        // @ts-ignore
        const { runMISPGalaxySync } = await import('../../../../worker/src/feeds/misp-galaxy');
        const r = await runMISPGalaxySync() as
            | { threatActors?: number; malware?: number; generic?: number; sigma?: number }
            | undefined;
        // MISP Galaxy writes to threat_actors + malware + galaxy_clusters
        // (called `generic` in the worker's return shape) + detection_rules
        // (sigma). On 2026-06-02 the prod sync added 9,735 galaxy_cluster
        // rows but the dashboard reported "0 items" because the headline
        // counter only tracked IOCs. This sums all four so the operator
        // sees the truth.
        const total = r
            ? (r.threatActors ?? 0) + (r.malware ?? 0) + (r.generic ?? 0) + (r.sigma ?? 0)
            : 0;
        return { ...emptyResult(true), totalRowsAffected: total };
    } catch (err) {
        return emptyResult(false, [(err as Error).message]);
    }
}

export async function syncEPSSFeed(): Promise<SyncResult> {
    // @ts-ignore — worker scripts outside rootDir, resolved at runtime
    const { syncEPSS } = await import('../../../../worker/src/feeds/epss');
    return normalise(await syncEPSS().then((r: { matched: number; failed: number; errors: string[] }) =>
        // EPSS reports `matched` (rows actually updated) as the meaningful
        // count; map it onto the standard `processed` field so the rest
        // of the pipeline (feed_sync_runs.items_ingested) reflects useful
        // work done rather than "rows present in the upstream feed".
        ({ processed: r.matched, failed: r.failed, errors: r.errors }),
    ));
}
