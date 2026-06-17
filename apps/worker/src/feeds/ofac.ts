/**
 * OFAC SDN — sanctioned cryptocurrency addresses (US Treasury)
 *
 * The one free, authoritative on-chain attribution source. Every digital-
 * currency address on the OFAC Specially Designated Nationals (SDN) list is a
 * ground-truth "this wallet belongs to a sanctioned entity" fact — exactly the
 * signal we'd otherwise pay Arkham for, but free and structured.
 *
 * Source: https://www.treasury.gov/ofac/downloads/sdn.xml  (no key, ~15 MB)
 * Format: XML. The crypto addresses live ONLY in the XML (the sdn.csv export
 *         drops the <idList> digital-currency entries), so this is a custom
 *         connector — the declarative feed-engine is JSON/CSV/text only.
 *
 * Each <sdnEntry> carries the entity name + sanctions programs + an <idList>;
 * we keep the <id> rows whose <idType> is "Digital Currency Address - <TICKER>".
 *
 * DUAL SINK (one pass):
 *   1. iocs   — type `crypto-address`, tagged `sanctioned` → feeds the Feeds
 *               page "Landscape shift" tag band + Indicators search + graph.
 *   2. wallets — entityType `sanctioned`, confidence 100, attributionSource
 *               `ofac` → the on-chain attribution layer (free Arkham stand-in).
 *
 * Updates: OFAC republishes on each designation action (irregular, days–weeks).
 * Daily is plenty; the upsert is idempotent on iocs.value / wallets.ref_id.
 */

import { XMLParser } from 'fast-xml-parser';
import { db, sql } from '@rinjani/db';
import { iocs, wallets } from '@rinjani/db/schema';
import type { NewWallet } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('OFAC');

const OFAC_SDN_XML_URL = process.env.OFAC_SDN_XML_URL
    ?? 'https://www.treasury.gov/ofac/downloads/sdn.xml';
const BATCH_SIZE = 200;

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

/**
 * Map an OFAC digital-currency ticker to our internal chain code. OFAC uses
 * `XBT` for Bitcoin; everything else is the common ticker. Unknowns fall
 * through to the lower-cased ticker so a newly-added asset still ingests.
 */
const CHAIN_BY_TICKER: Record<string, string> = {
    XBT: 'btc', BTC: 'btc', ETH: 'eth', USDT: 'usdt', USDC: 'usdc',
    XMR: 'xmr', LTC: 'ltc', ZEC: 'zec', DASH: 'dash', BTG: 'btg',
    ETC: 'etc', BSV: 'bsv', BCH: 'bch', XVG: 'xvg', XRP: 'xrp',
    TRX: 'trx', ARB: 'arb', BNB: 'bnb', SOL: 'sol',
};

/** Normalise fast-xml-parser's "string | object | array | undefined" to an array. */
function asArray<T>(v: T | T[] | undefined | null): T[] {
    if (v === undefined || v === null) return [];
    return Array.isArray(v) ? v : [v];
}

interface SanctionedAddress {
    address: string;
    chain: string;
    entityName: string;
    sdnType: string;        // Entity | Individual | Vessel | …
    programs: string[];     // e.g. ["CYBER2", "DPRK3"]
    uid: string;            // OFAC SDN UID — stable external ref
}

const DCA_RE = /Digital Currency Address\s*-\s*([A-Za-z0-9]+)/i;

/** Pull every digital-currency address out of the parsed SDN document. */
function extractAddresses(doc: unknown): SanctionedAddress[] {
    // <sdnList><sdnEntry>… ; fast-xml-parser strips the default namespace so
    // the local names come through verbatim.
    const root = (doc as { sdnList?: { sdnEntry?: unknown } })?.sdnList;
    const entries = asArray(root?.sdnEntry as Record<string, unknown> | Record<string, unknown>[]);
    const out: SanctionedAddress[] = [];

    for (const entry of entries) {
        const ids = asArray((entry.idList as { id?: unknown } | undefined)?.id as
            Record<string, unknown> | Record<string, unknown>[]);
        const crypto = ids.filter((id) => DCA_RE.test(String(id?.idType ?? '')));
        if (crypto.length === 0) continue;

        // Entity name: OFAC puts an org's full name in <lastName> with an empty
        // <firstName>; individuals split across both.
        const first = String(entry.firstName ?? '').trim();
        const last = String(entry.lastName ?? '').trim();
        const entityName = [first, last].filter(Boolean).join(' ') || `SDN ${String(entry.uid ?? '')}`;
        const sdnType = String(entry.sdnType ?? 'Entity').trim();
        const programs = asArray((entry.programList as { program?: unknown } | undefined)?.program)
            .map((p) => String(p).trim())
            .filter(Boolean);
        const uid = String(entry.uid ?? '').trim();

        for (const id of crypto) {
            const ticker = (String(id.idType).match(DCA_RE)?.[1] ?? '').toUpperCase();
            const address = String(id.idNumber ?? '').trim();
            if (!address) continue;
            out.push({
                address,
                chain: CHAIN_BY_TICKER[ticker] ?? ticker.toLowerCase(),
                entityName,
                sdnType,
                programs,
                uid,
            });
        }
    }
    return out;
}

async function fetchSdn(): Promise<SanctionedAddress[]> {
    const res = await fetch(OFAC_SDN_XML_URL, { headers: { Accept: 'application/xml' } });
    if (!res.ok) {
        throw new Error(`OFAC SDN fetch failed: ${res.status} ${res.statusText}`);
    }
    const xml = await res.text();
    const parser = new XMLParser({ ignoreAttributes: true, parseTagValue: false, trimValues: true });
    const doc = parser.parse(xml);
    return extractAddresses(doc);
}

export async function syncOFAC(): Promise<SyncResult> {
    log.info('Starting sync', { feedUrl: OFAC_SDN_XML_URL });
    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    let addresses: SanctionedAddress[];
    try {
        addresses = await fetchSdn();
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.error('Fetch/parse failed', err as Error);
        result.errors.push(`Fetch error: ${msg}`);
        result.failed = 1;
        return result;
    }
    log.info('Extracted sanctioned crypto addresses', { count: addresses.length });

    // De-dupe on chain:address — the same wallet can be listed under multiple
    // SDN entries; keep the first (programs differ but attribution is the same
    // "sanctioned" fact).
    const seen = new Set<string>();
    const unique = addresses.filter((a) => {
        const key = `${a.chain}:${a.address}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    for (let i = 0; i < unique.length; i += BATCH_SIZE) {
        const slice = unique.slice(i, i + BATCH_SIZE);
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

async function writeBatch(batch: SanctionedAddress[]): Promise<void> {
    const now = new Date();

    // --- IOC sink: surfaces in Landscape shift via the `sanctioned` tag ---
    const iocRows = batch.map((a) => ({
        type: 'crypto-address',
        value: a.address,
        source: 'ofac',
        threatType: 'sanctioned',
        confidence: 100, // OFAC SDN is authoritative ground truth
        severity: 'high',
        firstSeen: now,
        lastSeen: now,
        tags: [
            'ofac',
            'sanctioned',
            'ofac-sdn',
            a.chain,
            ...a.programs.map((p) => `ofac:${p.toLowerCase()}`),
        ],
        metadata: {
            chain: a.chain,
            entity: a.entityName,
            sdn_type: a.sdnType,
            programs: a.programs,
            sdn_uid: a.uid,
            feed_source: 'ofac',
        },
    }));

    await db.insert(iocs)
        .values(iocRows)
        .onConflictDoUpdate({
            target: iocs.value,
            set: { lastSeen: now, updatedAt: now },
        });

    // --- Wallet sink: the free on-chain attribution layer (Arkham stand-in) ---
    const walletRows: NewWallet[] = batch.map((a) => ({
        refId: `${a.chain}:${a.address}`,
        address: a.address,
        chain: a.chain,
        name: a.entityName,
        entityLabel: a.entityName,
        entityType: 'sanctioned',
        confidence: 100,
        attributionSource: 'ofac',
        riskTags: ['sanctioned', 'ofac-sdn', ...a.programs.map((p) => p.toLowerCase())],
        externalReferences: [{
            source_name: 'OFAC SDN',
            url: 'https://sanctionssearch.ofac.treas.gov/',
            external_id: a.uid,
        }],
    }));

    await db.insert(wallets)
        .values(walletRows)
        .onConflictDoUpdate({
            target: wallets.refId,
            set: {
                name: sql`excluded.name`,
                entityLabel: sql`excluded.entity_label`,
                entityType: sql`excluded.entity_type`,
                confidence: sql`excluded.confidence`,
                attributionSource: sql`excluded.attribution_source`,
                riskTags: sql`excluded.risk_tags`,
                updatedAt: now,
            },
        });
}

/** Standalone runner — `tsx apps/worker/src/feeds/ofac.ts`. */
export async function runOFACSync(): Promise<void> {
    log.info('Starting full sync');
    try {
        const result = await syncOFAC();
        log.info('Full sync completed', { processed: result.processed, failed: result.failed });
    } catch (error) {
        log.error('Sync failed', error as Error);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runOFACSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
