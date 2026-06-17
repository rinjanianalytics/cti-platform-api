/**
 * ScamSniffer scam-address blacklist — community-reported crypto scam wallets.
 *
 * #3 of the free on-chain roadmap. ScamSniffer (a well-known Web3 anti-scam
 * project) publishes an openly-licensed blacklist of addresses tied to
 * phishing/drainer/scam campaigns. Where OFAC gives *legal* ground-truth
 * (sanctioned), ScamSniffer gives *active fraud* coverage — the scam wallets
 * analysts actually run into. Together they harden the on-chain attribution
 * layer without paying Arkham.
 *
 * Source: https://raw.githubusercontent.com/scamsniffer/scam-database/main/
 *         blacklist/address.json  (no key — a flat JSON array of addresses,
 *         currently ~2.5k, all EVM/0x). Updated frequently upstream.
 *
 * NOT authoritative like OFAC: community/heuristic intel, so confidence is 75
 * (vs OFAC's 100), entity_type `scam` (vs `sanctioned`).
 *
 * DUAL SINK (mirrors ofac.ts):
 *   1. iocs   — type `crypto-address`, tagged `scam` → Landscape shift band.
 *   2. wallets — entityType `scam`, attributionSource `scamsniffer` → on-chain
 *               attribution layer (shows on the /onchain page).
 */

import { db, sql } from '@rinjani/db';
import { iocs, wallets } from '@rinjani/db/schema';
import type { NewWallet } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('ScamSniffer');

const SCAMSNIFFER_URL = process.env.SCAMSNIFFER_BLACKLIST_URL
    ?? 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json';
const BATCH_SIZE = 250;
// Community/heuristic intel — reputable but not legal ground-truth like OFAC.
const SCAM_CONFIDENCE = 75;

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

/** EVM address shape — the blacklist is currently all 0x/42-char. */
function isEvmAddress(a: string): boolean {
    return /^0x[a-fA-F0-9]{40}$/.test(a);
}

async function fetchBlacklist(): Promise<string[]> {
    const res = await fetch(SCAMSNIFFER_URL, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`ScamSniffer fetch failed: ${res.status} ${res.statusText}`);
    const body = await res.json() as unknown;
    if (!Array.isArray(body)) throw new Error('ScamSniffer blacklist is not a JSON array');
    // Normalise + de-dupe + keep only well-formed EVM addresses.
    const seen = new Set<string>();
    const out: string[] = [];
    for (const raw of body) {
        const addr = String(raw).trim().toLowerCase();
        if (!isEvmAddress(addr) || seen.has(addr)) continue;
        seen.add(addr);
        out.push(addr);
    }
    return out;
}

export async function syncScamSniffer(): Promise<SyncResult> {
    log.info('Starting sync', { feedUrl: SCAMSNIFFER_URL });
    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    let addresses: string[];
    try {
        addresses = await fetchBlacklist();
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.error('Fetch failed', err as Error);
        result.errors.push(`Fetch error: ${msg}`);
        result.failed = 1;
        return result;
    }
    log.info('Fetched scam addresses', { count: addresses.length });

    for (let i = 0; i < addresses.length; i += BATCH_SIZE) {
        const slice = addresses.slice(i, i + BATCH_SIZE);
        try {
            await writeBatch(slice);
            result.processed += slice.length;
        } catch (err) {
            result.failed += slice.length;
            const msg = err instanceof Error ? err.message : String(err);
            if (result.errors.length < 10) result.errors.push(`Batch insert failed: ${msg}`);
            log.error('Batch insert error', err as Error);
        }
    }

    log.info('Sync completed', { processed: result.processed, failed: result.failed });
    return result;
}

async function writeBatch(batch: string[]): Promise<void> {
    const now = new Date();

    // --- IOC sink: surfaces in Landscape shift via the `scam` tag ---
    const iocRows = batch.map((address) => ({
        type: 'crypto-address',
        value: address,
        source: 'scamsniffer',
        threatType: 'scam',
        confidence: SCAM_CONFIDENCE,
        severity: 'high',
        firstSeen: now,
        lastSeen: now,
        tags: ['scam', 'scamsniffer', 'phishing', 'eth'],
        metadata: { chain: 'eth', feed_source: 'scamsniffer' },
    }));

    await db.insert(iocs)
        .values(iocRows)
        .onConflictDoUpdate({
            target: iocs.value,
            set: { lastSeen: now, updatedAt: now },
        });

    // --- Wallet sink: on-chain attribution (shows on /onchain) ---
    const walletRows: NewWallet[] = batch.map((address) => ({
        refId: `eth:${address}`,
        address,
        chain: 'eth',
        name: 'Reported scam address',
        entityLabel: 'Reported scam address',
        entityType: 'scam',
        confidence: SCAM_CONFIDENCE,
        attributionSource: 'scamsniffer',
        riskTags: ['scam', 'scamsniffer', 'phishing'],
        externalReferences: [{
            source_name: 'ScamSniffer',
            url: 'https://github.com/scamsniffer/scam-database',
        }],
    }));

    await db.insert(wallets)
        .values(walletRows)
        .onConflictDoUpdate({
            target: wallets.refId,
            set: {
                // Don't clobber a higher-confidence attribution (e.g. an OFAC
                // sanctioned label, or an analyst's manual one) with the scam
                // tag — only upgrade when the existing confidence is lower.
                name: sql`CASE WHEN ${wallets.confidence} <= ${SCAM_CONFIDENCE} THEN excluded.name ELSE ${wallets.name} END`,
                entityLabel: sql`CASE WHEN ${wallets.confidence} <= ${SCAM_CONFIDENCE} THEN excluded.entity_label ELSE ${wallets.entityLabel} END`,
                entityType: sql`CASE WHEN ${wallets.confidence} <= ${SCAM_CONFIDENCE} THEN excluded.entity_type ELSE ${wallets.entityType} END`,
                confidence: sql`GREATEST(${wallets.confidence}, excluded.confidence)`,
                attributionSource: sql`CASE WHEN ${wallets.confidence} <= ${SCAM_CONFIDENCE} THEN excluded.attribution_source ELSE ${wallets.attributionSource} END`,
                updatedAt: now,
            },
        });
}

/** Standalone runner — `tsx apps/worker/src/feeds/scamsniffer.ts`. */
export async function runScamSnifferSync(): Promise<void> {
    log.info('Starting full sync');
    try {
        const result = await syncScamSniffer();
        log.info('Full sync completed', { processed: result.processed, failed: result.failed });
    } catch (error) {
        log.error('Sync failed', error as Error);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runScamSnifferSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
