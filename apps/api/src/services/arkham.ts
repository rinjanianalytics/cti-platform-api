/**
 * Arkham Intelligence adapter (AA.6.3 / Phase 8) — BYO-key on-chain attribution.
 *
 * A thin read-only client over the Arkham address-intelligence endpoint. No
 * Arkham data is bundled; the operator supplies ARKHAM_API_KEY (and optionally
 * ARKHAM_API_URL). The adapter "rides the tool plane" — it's a tool the agent
 * may call, never a feed that ingests bundled data.
 *
 * Wire contract (probed live 2026-06-16):
 *   GET {base}/intelligence/address/{address}?chain={chain}   header: API-Key
 *   → { address, chain, arkhamEntity: {name,type,id,service,...},
 *       arkhamLabel: {name,chainType}, isUserAddress, contract }
 *
 * Arkham returns NO numeric confidence — attribution is a curated CLAIM. We
 * surface the raw label/type; the caller (agent → human) assigns the
 * confidence when proposing a wallet, keeping attribution confidence-weighted.
 */

import { createLogger } from '../lib/logger';

const log = createLogger('Arkham');

const DEFAULT_BASE = 'https://api.arkhamintelligence.com';

export function isArkhamConfigured(): boolean {
    return !!process.env.ARKHAM_API_KEY;
}

export interface ArkhamAttribution {
    address: string;
    chain: string;
    entityName: string | null;   // "Binance", "Lazarus Group", "Vitalik Buterin"
    entityType: string | null;   // exchange | individual | … (Arkham's vocab)
    entityId: string | null;
    service: string | null;      // e.g. "Binance" for an exchange-owned address
    label: string | null;        // arkhamLabel.name, e.g. "vitalik.eth"
    isUserAddress: boolean;
    isContract: boolean;
    /** True when Arkham has no entity/label for the address (unattributed). */
    unattributed: boolean;
}

interface ArkhamRaw {
    address?: string;
    chain?: string;
    arkhamEntity?: { name?: string; type?: string; id?: string; service?: string | null } | null;
    arkhamLabel?: { name?: string } | null;
    isUserAddress?: boolean;
    contract?: boolean;
}

/** Look up an address's Arkham attribution. Throws if unconfigured or on API error. */
export async function lookupAddress(address: string, chain = 'ethereum'): Promise<ArkhamAttribution> {
    const key = process.env.ARKHAM_API_KEY;
    if (!key) throw new Error('Arkham not configured — set ARKHAM_API_KEY to use on-chain lookup');

    const base = process.env.ARKHAM_API_URL || DEFAULT_BASE;
    const url = `${base}/intelligence/address/${encodeURIComponent(address)}?chain=${encodeURIComponent(chain)}`;

    const res = await fetch(url, { headers: { 'API-Key': key }, signal: AbortSignal.timeout(15000) });
    if (!res.ok) {
        throw new Error(`Arkham ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    const d = (await res.json()) as ArkhamRaw;
    const entityName = d.arkhamEntity?.name ?? null;
    const label = d.arkhamLabel?.name ?? null;
    log.info('Arkham lookup', { address, chain, entity: entityName, label });
    return {
        address: d.address ?? address,
        chain: d.chain ?? chain,
        entityName,
        entityType: d.arkhamEntity?.type ?? null,
        entityId: d.arkhamEntity?.id ?? null,
        service: d.arkhamEntity?.service ?? null,
        label,
        isUserAddress: !!d.isUserAddress,
        isContract: !!d.contract,
        unattributed: !entityName && !label,
    };
}

/** Exposed for tests. */
export const __testing = { DEFAULT_BASE };
