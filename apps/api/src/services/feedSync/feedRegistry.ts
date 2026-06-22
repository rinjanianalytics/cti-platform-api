/**
 * Feed Registry — Pluggable feed dispatch map
 *
 * Maps feed source keys → sync handler functions.
 * Adding a new feed is a one-liner here — no worker changes needed.
 *
 * Engine-backed dispatch (A3): the worker calls resolveFeedHandler() instead
 * of getFeedHandler() directly. resolveFeedHandler consults FEED_ENGINE_ENABLED
 * + the feed_manifest table; only if both gates pass for a source does it
 * return the engine-backed handler. Every other call path falls through to
 * the legacy registry below — no shipped feed changes behavior unless the
 * operator opts a source in by activating a manifest AND flipping the flag.
 */

import type { SyncResult } from './types';
import { syncOTXFeed } from './otxSync';
import { syncCISAFeed } from './cisaSync';
import { syncNVDFeed } from './nvdSync';
import { syncCveOrgFeed } from './cveOrgSync';
import {
    syncAbuseSSLFeed, syncThreatFoxFeed, syncURLhausFeed,
    syncMalwareBazaarFeed, syncOpenPhishFeed, syncMITREFeed, syncMISPGalaxyFeed,
    syncEPSSFeed, syncOFACFeed, syncAIIncidentsFeed, syncScamSnifferFeed, syncDefiLlamaFeed,
    syncTelcoNewsFeed, syncIntelNewsFeed,
} from './additionalFeeds';
import { syncHibpBreaches } from './hibpSync';
import { FeedManifest as FeedManifestSchema } from '@rinjani/feed-engine';
import { createLogger } from '../../lib/logger';

const log = createLogger('FeedRegistry');

export type FeedSyncOptions = { limit?: number; since?: string };
export type FeedHandler = (opts?: FeedSyncOptions) => Promise<SyncResult>;

/**
 * Central registry mapping source keys to their sync handler functions.
 * Each handler returns a uniform SyncResult.
 */
const FEED_REGISTRY: Record<string, FeedHandler> = {
    otx: (opts) => syncOTXFeed(opts),
    cisa: (opts) => syncCISAFeed(opts),
    // CVE.org cvelistV5 is the *primary* CVE ingest — fresh within
    // minutes of CNA disclosure. NVD becomes a CVSS-score fallback only.
    cveorg: (opts) => syncCveOrgFeed(opts),
    nvd: (opts) => syncNVDFeed(opts),
    abusessl: () => syncAbuseSSLFeed(),
    threatfox: () => syncThreatFoxFeed(),
    urlhaus: () => syncURLhausFeed(),
    malwarebazaar: () => syncMalwareBazaarFeed(),
    openphish: () => syncOpenPhishFeed(),
    // OFAC SDN sanctioned crypto addresses — the one free, authoritative
    // on-chain attribution source. Dual-sinks to iocs (tag `sanctioned`,
    // surfaces in Landscape shift) + wallets (entityType `sanctioned`).
    ofac: () => syncOFACFeed(),
    // AI Incident Database — real-world AI harm/failure incidents
    // (incidentdatabase.ai). The live AI-threat-landscape signal; sinks to
    // the dedicated ai_incidents table.
    aiid: () => syncAIIncidentsFeed(),
    // ScamSniffer community scam-address blacklist — active-fraud on-chain
    // coverage. Dual-sinks to iocs (tag `scam`) + wallets (entityType `scam`),
    // mirroring OFAC. Community intel, confidence 75 (vs OFAC's 100).
    scamsniffer: () => syncScamSnifferFeed(),
    // DefiLlama protocol labels — benign on-chain attribution (defi-typed
    // wallet labels) so the free lookup resolves protocol addresses DB-first.
    defillama: () => syncDefiLlamaFeed(),
    mitre: () => syncMITREFeed(),
    mispgalaxy: () => syncMISPGalaxyFeed(),
    // EPSS — FIRST.org's daily exploit-prediction score. Pairs with the
    // CVE feeds above: NVD/CVE.org give us the CVEs, EPSS gives us
    // "which of those is likely to be exploited in the next 30 days".
    epss: () => syncEPSSFeed(),
    // HIBP — haveibeenpwned.com's vetted breach catalog. Free-tier only:
    // `/breaches` returns the full list (~700 entries). The per-account
    // `/breachedaccount` endpoint requires a paid key and is intentionally
    // out of scope.
    hibp: () => syncHibpBreaches(),
    // Tier-2 telco intel — telecom-keyword-filtered security news (RSS) → the
    // telco_advisories table, unioned into /v1/telco/intel.
    telconews: () => syncTelcoNewsFeed(),
    // Broad threat-intel narrative ingestion (RSS) — curated CTI sources →
    // intel_reports. Phase 1 of RSS + extraction (collection only); Phase 2
    // pulls actor→technique TTPs out of these into actor_ttp_changes.
    intelnews: () => syncIntelNewsFeed(),
};

/** Get the sync handler for a specific feed source. */
export function getFeedHandler(source: string): FeedHandler | undefined {
    return FEED_REGISTRY[source];
}

/** Get all registered feed source keys. */
export function getRegisteredFeeds(): string[] {
    return Object.keys(FEED_REGISTRY);
}

/** Check if a feed source is registered. */
export function isFeedRegistered(source: string): boolean {
    return source in FEED_REGISTRY;
}

/**
 * Async dispatch with engine fallback (A3 entry point).
 *
 * Resolution order:
 *   1. If FEED_ENGINE_ENABLED is not 'true' → legacy handler (env kill switch).
 *   2. If no active manifest for `source` → legacy handler.
 *   3. If active manifest's entity is not 'ioc' → legacy + warn (A3 is IOC-only;
 *      A4+ widen).
 *   4. If manifest body fails the engine schema → legacy + warn (the manifest
 *      was authored before a schema tightening, or directly mutated in DB).
 *   5. Otherwise → engine-backed handler.
 *
 * The legacy fallback is deliberate: A3 must never break a shipped feed.
 * Operators opt in per-source by activating a manifest, then flip the env
 * flag globally when ready.
 */
export async function resolveFeedHandler(source: string): Promise<FeedHandler | undefined> {
    const legacy = getFeedHandler(source);

    if (process.env.FEED_ENGINE_ENABLED !== 'true') {
        return legacy;
    }

    // Lazy import keeps the worker boot path from pulling DB drivers when
    // the flag is off (matches the auditMiddleware lazy-import pattern).
    let activeManifest: { id: string; entity: string; manifest: Record<string, unknown> } | undefined;
    try {
        const { listManifests } = await import('../connectorStore');
        const rows = await listManifests({ source, activeOnly: true });
        if (rows[0]) {
            activeManifest = { id: rows[0].id, entity: rows[0].entity, manifest: rows[0].manifest };
        }
    } catch (err) {
        log.warn('Engine dispatch lookup failed, falling back to legacy', {
            source, error: (err as Error).message,
        });
        return legacy;
    }

    if (!activeManifest) return legacy;

    // Supported entities widen with each A7.N migration. Sinks live in
    // services/feedSync/engineHandler.ts — adding a new entity is a sink
    // function there + adding the value here.
    const SUPPORTED_ENGINE_ENTITIES = new Set(['ioc', 'vulnerability']);
    if (!SUPPORTED_ENGINE_ENTITIES.has(activeManifest.entity)) {
        log.warn('Engine handler unavailable for this entity; falling back to legacy', {
            source, entity: activeManifest.entity,
            supported: Array.from(SUPPORTED_ENGINE_ENTITIES),
        });
        return legacy;
    }

    const parsed = FeedManifestSchema.safeParse(activeManifest.manifest);
    if (!parsed.success) {
        log.warn('Active manifest failed engine schema; falling back to legacy', {
            source,
            issues: parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`),
        });
        return legacy;
    }

    log.info('Engine dispatch: using engine-backed handler', { source, manifestId: activeManifest.id });

    // Lazy import to keep engineHandler off the legacy boot path entirely.
    const { buildEngineHandler } = await import('./engineHandler');
    return buildEngineHandler(parsed.data, activeManifest.id);
}
