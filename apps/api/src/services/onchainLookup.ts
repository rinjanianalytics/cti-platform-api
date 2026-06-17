/**
 * Free multi-source on-chain attribution aggregator (replaces the paid Arkham
 * adapter). Given an address, it fans out to several FREE sources in parallel
 * and merges them into one confidence-weighted, provenance-tagged attribution:
 *
 *   1. Our own wallets DB   — OFAC sanctioned / ScamSniffer scam / analyst /
 *                             feed-ingested labels (instant, authoritative).
 *   2. Blockscout           — open-source explorer; contract name, is-contract,
 *                             token info, public tags (REST v2; optional
 *                             BLOCKSCOUT_API_KEY just raises the rate limit).
 *   3. DefiLlama            — 7.6k protocols → name + category (free REST).
 *   4. MistTrack (SlowMist) — OPTIONAL BYO-key: entity label + AML risk score.
 *                             Activates only when MISTTRACK_API_KEY is set;
 *                             degrades gracefully otherwise.
 *
 * Every source is wrapped so a failure never breaks the lookup — worst case a
 * source contributes nothing (mirrors the rag.search graceful-degradation
 * pattern). Attribution stays a CLAIM: each label rides with its `source`, and
 * only our DB carries a numeric `confidence`.
 */

import { createLogger } from '../lib/logger';
import { getWalletByRef } from './onchainStore';

const log = createLogger('OnchainLookup');

/** Back-compat with the old ArkhamAttribution shape (the agent tool + dashboard
 *  read these fields), plus the new multi-source fields. */
export interface OnchainAttribution {
    address: string;
    chain: string;
    entityName: string | null;
    entityType: string | null;
    label: string | null;
    isContract: boolean;
    unattributed: boolean;
    // multi-source additions
    confidence: number | null;          // only our DB carries one
    riskScore: number | null;           // MistTrack 3–100, if available
    riskLevel: string | null;           // MistTrack Low|Moderate|High|Severe
    tags: string[];                     // union of risk/label tags across sources
    sources: AttributionSource[];       // provenance — which source said what
    // legacy fields kept so nothing downstream breaks
    entityId: string | null;
    service: string | null;
    isUserAddress: boolean;
}

interface AttributionSource {
    source: string;                     // ofac | scamsniffer | blockscout | defillama | misttrack | …
    label?: string | null;
    type?: string | null;
    detail?: string | null;
}

/** A single source's contribution + its merge precedence tier (lower wins). */
interface Hit {
    tier: number;                       // 0 db · 1 misttrack · 2 defillama · 3 blockscout
    partial: Partial<OnchainAttribution>;
    source: AttributionSource;
}

const BLOCKSCOUT_BASE: Record<string, string> = {
    ethereum: 'https://eth.blockscout.com',
    eth: 'https://eth.blockscout.com',
    base: 'https://base.blockscout.com',
    optimism: 'https://optimism.blockscout.com',
    gnosis: 'https://gnosis.blockscout.com',
    polygon: 'https://polygon.blockscout.com',
};

const MISTTRACK_COIN: Record<string, string> = {
    ethereum: 'ETH', eth: 'ETH', bitcoin: 'BTC', btc: 'BTC',
    tron: 'TRX', trx: 'TRX', bsc: 'BSC', polygon: 'MATIC',
};

const isEvm = (a: string) => /^0x[a-fA-F0-9]{40}$/.test(a);

// ---- source 1: our wallets DB -------------------------------------------------
async function fromDb(chain: string, address: string): Promise<Hit | null> {
    const w = await getWalletByRef(`${chain}:${address.toLowerCase()}`);
    if (!w) return null;
    return {
        tier: 0,
        partial: {
            entityName: w.entityLabel ?? w.name ?? null,
            entityType: w.entityType ?? null,
            confidence: w.confidence ?? null,
            tags: w.riskTags ?? [],
        },
        source: { source: w.attributionSource ?? 'db', label: w.entityLabel, type: w.entityType },
    };
}

// ---- source 2: Blockscout (open-source explorer) -----------------------------
interface BlockscoutAddr {
    name?: string | null;
    is_contract?: boolean;
    public_tags?: Array<{ display_name?: string }> | null;
    token?: { name?: string | null; symbol?: string | null } | null;
}
async function fromBlockscout(chain: string, address: string): Promise<Hit | null> {
    if (!isEvm(address)) return null;
    const base = process.env.BLOCKSCOUT_BASE || BLOCKSCOUT_BASE[chain] || BLOCKSCOUT_BASE.ethereum;
    // BLOCKSCOUT_API_KEY is OPTIONAL — it only raises the rate limit. Passed as
    // the `?apikey=` query param (Blockscout convention); keyless still works.
    const apiKey = process.env.BLOCKSCOUT_API_KEY;
    const url = `${base}/api/v2/addresses/${address}${apiKey ? `?apikey=${encodeURIComponent(apiKey)}` : ''}`;
    const res = await fetch(url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    const d = (await res.json()) as BlockscoutAddr;
    const tagName = d.public_tags?.[0]?.display_name ?? null;
    const name = tagName ?? d.token?.name ?? d.name ?? null;
    if (!name && !d.is_contract) return null;
    return {
        tier: 3,
        partial: {
            entityName: name,
            entityType: d.token ? 'token' : d.is_contract ? 'contract' : null,
            isContract: !!d.is_contract,
        },
        source: { source: 'blockscout', label: name, type: d.token ? 'token' : d.is_contract ? 'contract' : null },
    };
}

// ---- source 3: DefiLlama (protocol → address map, cached) ---------------------
interface LlamaProtocol { name?: string; address?: string | null; category?: string; chain?: string }
let llamaCache: { at: number; map: Map<string, { name: string; category: string }> } | null = null;
const LLAMA_TTL = 60 * 60 * 1000; // 1h

async function loadLlama(): Promise<Map<string, { name: string; category: string }>> {
    if (llamaCache && Date.now() - llamaCache.at < LLAMA_TTL) return llamaCache.map;
    const res = await fetch('https://api.llama.fi/protocols', { signal: AbortSignal.timeout(15000) });
    if (!res.ok) throw new Error(`defillama ${res.status}`);
    const protocols = (await res.json()) as LlamaProtocol[];
    const map = new Map<string, { name: string; category: string }>();
    for (const p of protocols) {
        if (!p.address || !p.name) continue;
        // address may be "0x.." or "chain:0x.." — key on the trailing 0x part.
        const addr = p.address.split(':').pop()!.toLowerCase();
        if (isEvm(addr)) map.set(addr, { name: p.name, category: p.category ?? 'defi' });
    }
    llamaCache = { at: Date.now(), map };
    return map;
}
async function fromDefiLlama(address: string): Promise<Hit | null> {
    if (!isEvm(address)) return null;
    const hit = (await loadLlama()).get(address.toLowerCase());
    if (!hit) return null;
    return {
        tier: 2,
        partial: { entityName: hit.name, entityType: 'defi', tags: [hit.category.toLowerCase()] },
        source: { source: 'defillama', label: hit.name, type: hit.category },
    };
}

// ---- source 4: MistTrack (SlowMist) — OPTIONAL BYO-key -----------------------
async function fromMistTrack(chain: string, address: string): Promise<Hit | null> {
    const key = process.env.MISTTRACK_API_KEY;
    if (!key) return null;
    const coin = MISTTRACK_COIN[chain] ?? 'ETH';
    const base = process.env.MISTTRACK_API_URL || 'https://openapi.misttrack.io';
    const qs = `coin=${coin}&address=${encodeURIComponent(address)}&api_key=${encodeURIComponent(key)}`;

    const [labelsRes, riskRes] = await Promise.allSettled([
        fetch(`${base}/v1/address_labels?${qs}`, { signal: AbortSignal.timeout(12000) }).then(r => r.json()),
        fetch(`${base}/v3/risk_score?${qs}`, { signal: AbortSignal.timeout(12000) }).then(r => r.json()),
    ]);

    // MistTrack wraps payloads as { success, data }. Tolerate either shape.
    const unwrap = (r: PromiseSettledResult<unknown>): Record<string, unknown> => {
        if (r.status !== 'fulfilled' || !r.value || typeof r.value !== 'object') return {};
        const v = r.value as Record<string, unknown>;
        return (v.data && typeof v.data === 'object' ? v.data : v) as Record<string, unknown>;
    };
    const labels = unwrap(labelsRes);
    const risk = unwrap(riskRes);

    const labelList = Array.isArray(labels.label_list) ? (labels.label_list as string[]) : [];
    const labelType = typeof labels.label_type === 'string' ? labels.label_type : null;
    const entity = (typeof risk.address_label === 'string' && risk.address_label) || labelList[0] || null;
    const score = typeof risk.score === 'number' ? risk.score : null;
    const riskLevel = typeof risk.risk_level === 'string' ? risk.risk_level : null;

    if (!entity && labelList.length === 0 && score == null) return null;
    return {
        tier: 1,
        partial: {
            entityName: entity,
            entityType: labelType || null,
            riskScore: score,
            riskLevel,
            tags: labelList,
        },
        source: { source: 'misttrack', label: entity, type: labelType, detail: riskLevel },
    };
}

/**
 * Resolve an address's attribution across all configured free sources.
 * Never throws — sources that error simply don't contribute.
 */
export async function lookupAddress(address: string, chain = 'ethereum'): Promise<OnchainAttribution> {
    const results = await Promise.allSettled([
        fromDb(chain, address),
        fromBlockscout(chain, address),
        fromDefiLlama(address),
        fromMistTrack(chain, address),
    ]);

    const hits = results
        .map((r, i) => {
            if (r.status === 'fulfilled') return r.value;
            log.warn('onchain source failed', { source: ['db', 'blockscout', 'defillama', 'misttrack'][i], error: (r.reason as Error)?.message });
            return null;
        })
        .filter((h): h is Hit => h != null);

    // Merge by explicit tier (DB 0 > MistTrack 1 > DefiLlama 2 > Blockscout 3).
    // First non-null per field wins — so our curated/sanctioned DB labels never
    // get overwritten by a generic explorer name.
    const ordered = [...hits].sort((a, b) => a.tier - b.tier);

    const merged: OnchainAttribution = {
        address, chain,
        entityName: null, entityType: null, label: null, isContract: false, unattributed: true,
        confidence: null, riskScore: null, riskLevel: null, tags: [], sources: [],
        entityId: null, service: null, isUserAddress: false,
    };
    const tagSet = new Set<string>();
    for (const h of ordered) {
        const p = h.partial;
        merged.entityName ??= p.entityName ?? null;
        merged.entityType ??= p.entityType ?? null;
        merged.confidence ??= p.confidence ?? null;
        merged.riskScore ??= p.riskScore ?? null;
        merged.riskLevel ??= p.riskLevel ?? null;
        if (p.isContract) merged.isContract = true;
        for (const t of p.tags ?? []) if (t) tagSet.add(t);
        merged.sources.push(h.source);
    }
    merged.tags = [...tagSet];
    merged.label = merged.entityName;
    merged.unattributed = !merged.entityName && merged.tags.length === 0 && merged.riskScore == null;

    log.info('onchain lookup', {
        address, chain, entity: merged.entityName, sources: merged.sources.map(s => s.source),
    });
    return merged;
}
