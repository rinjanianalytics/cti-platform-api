/**
 * Feed Registry — Pluggable feed dispatch map
 *
 * Maps feed source keys → sync handler functions.
 * Adding a new feed is a one-liner here — no worker changes needed.
 */

import type { SyncResult } from './types';
import { syncOTXFeed } from './otxSync';
import { syncCISAFeed } from './cisaSync';
import { syncNVDFeed } from './nvdSync';
import { syncCveOrgFeed } from './cveOrgSync';
import {
    syncAbuseSSLFeed, syncThreatFoxFeed, syncURLhausFeed,
    syncMalwareBazaarFeed, syncOpenPhishFeed, syncMITREFeed, syncMISPGalaxyFeed,
} from './additionalFeeds';

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
    mitre: () => syncMITREFeed(),
    mispgalaxy: () => syncMISPGalaxyFeed(),
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
