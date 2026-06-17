/**
 * DefiLlama protocol-label feed — free benign on-chain attribution.
 *
 * DefiLlama publishes ~7.7k DeFi protocols (free REST, no key), ~4k of which
 * carry a governance/contract address. We ingest those as `defi`-typed wallet
 * labels so the on-chain attribution layer resolves "0x… → Lido / Aave / …"
 * DB-first, without an external call per lookup.
 *
 * Source: https://api.llama.fi/protocols
 *
 * BENIGN labels (a protocol identity, not a threat) → sink to `wallets` ONLY,
 * NOT to iocs. (OFAC/ScamSniffer dual-sink to iocs because they're malicious;
 * labelling Uniswap as an IOC would pollute the indicator feed + landscape
 * shift.) Confidence 70 — factual public labels, but lower than OFAC's
 * authoritative 100. The upsert is confidence-preserving so a DefiLlama label
 * never overwrites a sanctioned/scam attribution.
 */

import { db, sql } from '@rinjani/db';
import { wallets } from '@rinjani/db/schema';
import type { NewWallet } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('DefiLlama');

const DEFILLAMA_URL = process.env.DEFILLAMA_PROTOCOLS_URL ?? 'https://api.llama.fi/protocols';
const BATCH_SIZE = 250;
const LABEL_CONFIDENCE = 70;

interface SyncResult { processed: number; failed: number; errors: string[] }

interface LlamaProtocol {
    name?: string;
    address?: string | null;
    category?: string;
    chain?: string;
}

/** DefiLlama chain name → our internal chain code (EVM only; others skipped). */
const CHAIN_CODE: Record<string, string> = {
    ethereum: 'eth', base: 'base', optimism: 'optimism', arbitrum: 'arbitrum',
    polygon: 'polygon', bsc: 'bsc', gnosis: 'gnosis', avalanche: 'avax', fantom: 'fantom',
};

const isEvm = (a: string) => /^0x[a-fA-F0-9]{40}$/.test(a);

/** Resolve (chain, address) from DefiLlama's `address` ("0x.." or "chain:0x..")
 *  + the protocol's primary chain. Returns null for non-EVM / malformed. */
function resolve(p: LlamaProtocol): { chain: string; address: string } | null {
    if (!p.address) return null;
    let chain = 'eth';
    let addr = p.address.trim();
    if (addr.includes(':')) {
        const [prefix, rest] = [addr.slice(0, addr.indexOf(':')), addr.slice(addr.indexOf(':') + 1)];
        chain = CHAIN_CODE[prefix.toLowerCase()] ?? prefix.toLowerCase();
        addr = rest;
    } else if (p.chain && p.chain !== 'Multi-Chain') {
        // Bare address: trust the protocol's single chain when it has one;
        // Multi-Chain protocols list their address on Ethereum mainnet.
        chain = CHAIN_CODE[p.chain.toLowerCase()] ?? 'eth';
    }
    addr = addr.toLowerCase();
    return isEvm(addr) ? { chain, address: addr } : null;
}

async function fetchProtocols(): Promise<LlamaProtocol[]> {
    const res = await fetch(DEFILLAMA_URL, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`DefiLlama fetch failed: ${res.status} ${res.statusText}`);
    const body = await res.json() as unknown;
    if (!Array.isArray(body)) throw new Error('DefiLlama protocols is not a JSON array');
    return body as LlamaProtocol[];
}

export async function syncDefiLlama(): Promise<SyncResult> {
    log.info('Starting sync', { feedUrl: DEFILLAMA_URL });
    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    let protocols: LlamaProtocol[];
    try {
        protocols = await fetchProtocols();
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.error('Fetch failed', err as Error);
        result.errors.push(`Fetch error: ${msg}`);
        result.failed = 1;
        return result;
    }

    // Map → wallet rows, de-duped on ref_id (a few protocols share an address).
    const seen = new Set<string>();
    const rows: NewWallet[] = [];
    for (const p of protocols) {
        if (!p.name) continue;
        const r = resolve(p);
        if (!r) continue;
        const refId = `${r.chain}:${r.address}`;
        if (seen.has(refId)) continue;
        seen.add(refId);
        const category = (p.category ?? 'defi').toLowerCase();
        rows.push({
            refId,
            address: r.address,
            chain: r.chain,
            name: p.name,
            entityLabel: p.name,
            entityType: 'defi',
            confidence: LABEL_CONFIDENCE,
            attributionSource: 'defillama',
            riskTags: ['defi', 'defillama', category],
            externalReferences: [{ source_name: 'DefiLlama', url: 'https://defillama.com' }],
        });
    }
    log.info('Resolved protocol labels', { count: rows.length, of: protocols.length });

    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
        const slice = rows.slice(i, i + BATCH_SIZE);
        try {
            await writeBatch(slice);
            result.processed += slice.length;
        } catch (err) {
            result.failed += slice.length;
            const msg = err instanceof Error ? err.message : String(err);
            if (result.errors.length < 10) result.errors.push(`Batch upsert failed: ${msg}`);
            log.error('Batch upsert error', err as Error);
        }
    }

    log.info('Sync completed', { processed: result.processed, failed: result.failed });
    return result;
}

async function writeBatch(batch: NewWallet[]): Promise<void> {
    const now = new Date();
    await db.insert(wallets)
        .values(batch)
        .onConflictDoUpdate({
            target: wallets.refId,
            set: {
                // Confidence-preserving: never overwrite a higher-confidence
                // attribution (OFAC sanctioned 100, ScamSniffer 75, analyst) with
                // a benign protocol label.
                name: sql`CASE WHEN ${wallets.confidence} <= ${LABEL_CONFIDENCE} THEN excluded.name ELSE ${wallets.name} END`,
                entityLabel: sql`CASE WHEN ${wallets.confidence} <= ${LABEL_CONFIDENCE} THEN excluded.entity_label ELSE ${wallets.entityLabel} END`,
                entityType: sql`CASE WHEN ${wallets.confidence} <= ${LABEL_CONFIDENCE} THEN excluded.entity_type ELSE ${wallets.entityType} END`,
                confidence: sql`GREATEST(${wallets.confidence}, excluded.confidence)`,
                attributionSource: sql`CASE WHEN ${wallets.confidence} <= ${LABEL_CONFIDENCE} THEN excluded.attribution_source ELSE ${wallets.attributionSource} END`,
                updatedAt: now,
            },
        });
}

/** Standalone runner — `tsx apps/worker/src/feeds/defillama.ts`. */
export async function runDefiLlamaSync(): Promise<void> {
    log.info('Starting full sync');
    try {
        const result = await syncDefiLlama();
        log.info('Full sync completed', { processed: result.processed, failed: result.failed });
    } catch (error) {
        log.error('Sync failed', error as Error);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runDefiLlamaSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
