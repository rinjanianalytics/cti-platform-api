/**
 * Telco entity store — B1.1 CRUD for the three telco-domain tables.
 *
 * network_elements / signaling_interfaces / fraud_schemes. Operator-entered
 * for now (no feed ingest until B1.4). Create is an idempotent upsert on the
 * natural key `ref_id` so re-POSTing the same entity updates rather than
 * duplicates — the pattern feeds will reuse in B1.4.
 *
 * No graph hydration here: telco entities become graph-participating only when
 * relationships referencing them are inserted (B1.2). This module is pure
 * relational CRUD.
 */

import { db, eq, desc, ilike, and, sql } from '@rinjani/db';
import { networkElements, signalingInterfaces, fraudSchemes } from '@rinjani/db/schema';
import type {
    NetworkElement, NewNetworkElement,
    SignalingInterface, NewSignalingInterface,
    FraudScheme, NewFraudScheme,
} from '@rinjani/db/schema';

// ----------------------------------------------------------------------------
// Network elements
// ----------------------------------------------------------------------------

export async function upsertNetworkElement(data: NewNetworkElement): Promise<NetworkElement> {
    const [row] = await db
        .insert(networkElements)
        .values(data)
        .onConflictDoUpdate({
            target: networkElements.refId,
            set: { ...data, updatedAt: new Date() },
        })
        .returning();
    return row;
}

export async function listNetworkElements(filters: {
    elementType?: string;
    q?: string;
    limit?: number;
} = {}): Promise<NetworkElement[]> {
    const conds = [];
    if (filters.elementType) conds.push(eq(networkElements.elementType, filters.elementType));
    if (filters.q) conds.push(ilike(networkElements.name, `%${filters.q}%`));
    return db
        .select()
        .from(networkElements)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(networkElements.createdAt))
        .limit(Math.min(filters.limit ?? 100, 500));
}

export async function getNetworkElement(id: string): Promise<NetworkElement | null> {
    const rows = await db.select().from(networkElements).where(eq(networkElements.id, id)).limit(1);
    return rows[0] ?? null;
}

export async function deleteNetworkElement(id: string): Promise<boolean> {
    const out = await db.delete(networkElements).where(eq(networkElements.id, id)).returning({ id: networkElements.id });
    return out.length > 0;
}

// ----------------------------------------------------------------------------
// Signaling interfaces
// ----------------------------------------------------------------------------

export async function upsertSignalingInterface(data: NewSignalingInterface): Promise<SignalingInterface> {
    const [row] = await db
        .insert(signalingInterfaces)
        .values(data)
        .onConflictDoUpdate({
            target: signalingInterfaces.refId,
            set: { ...data, updatedAt: new Date() },
        })
        .returning();
    return row;
}

export async function listSignalingInterfaces(filters: {
    protocol?: string;
    q?: string;
    limit?: number;
} = {}): Promise<SignalingInterface[]> {
    const conds = [];
    if (filters.protocol) conds.push(eq(signalingInterfaces.protocol, filters.protocol));
    if (filters.q) conds.push(ilike(signalingInterfaces.name, `%${filters.q}%`));
    return db
        .select()
        .from(signalingInterfaces)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(signalingInterfaces.createdAt))
        .limit(Math.min(filters.limit ?? 100, 500));
}

export async function getSignalingInterface(id: string): Promise<SignalingInterface | null> {
    const rows = await db.select().from(signalingInterfaces).where(eq(signalingInterfaces.id, id)).limit(1);
    return rows[0] ?? null;
}

export async function deleteSignalingInterface(id: string): Promise<boolean> {
    const out = await db.delete(signalingInterfaces).where(eq(signalingInterfaces.id, id)).returning({ id: signalingInterfaces.id });
    return out.length > 0;
}

// ----------------------------------------------------------------------------
// Fraud schemes
// ----------------------------------------------------------------------------

export async function upsertFraudScheme(data: NewFraudScheme): Promise<FraudScheme> {
    const [row] = await db
        .insert(fraudSchemes)
        .values(data)
        .onConflictDoUpdate({
            target: fraudSchemes.refId,
            set: { ...data, updatedAt: new Date() },
        })
        .returning();
    return row;
}

export async function listFraudSchemes(filters: {
    schemeType?: string;
    q?: string;
    // B1.3 — JSONB containment filters. `gsma_fs_categories @> '["FS.11"]'`
    // and `three_gpp_threats @> '["TR 33.926"]'`. GIN-indexed (migration 0062).
    gsmaCategory?: string;
    threeGpp?: string;
    limit?: number;
} = {}): Promise<FraudScheme[]> {
    const conds = [];
    if (filters.schemeType) conds.push(eq(fraudSchemes.schemeType, filters.schemeType));
    if (filters.q) conds.push(ilike(fraudSchemes.name, `%${filters.q}%`));
    if (filters.gsmaCategory) {
        conds.push(sql`${fraudSchemes.gsmaFsCategories} @> ${JSON.stringify([filters.gsmaCategory])}::jsonb`);
    }
    if (filters.threeGpp) {
        conds.push(sql`${fraudSchemes.threeGppThreats} @> ${JSON.stringify([filters.threeGpp])}::jsonb`);
    }
    return db
        .select()
        .from(fraudSchemes)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(fraudSchemes.createdAt))
        .limit(Math.min(filters.limit ?? 100, 500));
}

export async function getFraudScheme(id: string): Promise<FraudScheme | null> {
    const rows = await db.select().from(fraudSchemes).where(eq(fraudSchemes.id, id)).limit(1);
    return rows[0] ?? null;
}

export async function deleteFraudScheme(id: string): Promise<boolean> {
    const out = await db.delete(fraudSchemes).where(eq(fraudSchemes.id, id)).returning({ id: fraudSchemes.id });
    return out.length > 0;
}

// =============================================================================
// Telco threat intel (Tier-1) — NO new feed: filter the data we already ingest.
// OTX pulses tagged/described with telecom terms + CVEs against telecom-pure
// vendors (or whose product mentions a mobile-core term). Gives the Telco
// vertical live signal beyond the static FiGHT seed, for free.
// =============================================================================

export interface TelcoIntelItem {
    kind: 'pulse' | 'cve';
    id: string;
    title: string;
    ref: string;
    severity: string | null;
    tags: string[];
    /** Event/publish date (pulse modified · CVE published). */
    date: string | null;
    /** When WE ingested it (the "Added" signal). */
    added: string | null;
    source: string;
}

// Telecom context terms (case-insensitive regex). Kept specific to avoid
// false positives — generic words like "ran"/"sip"/"ims" are intentionally out.
const TELCO_KW =
    'telecom|telco|5g|ss7|diameter|\\mgtp\\M|signal+ing|baseband|enodeb|gnodeb|gnb|volte|roaming|simjacker|sim.?swap|salt typhoon|o-?ran|open5gs|srsran|packet core|mobile network|subscriber';
// Telecom-pure equipment/core vendors (broad vendors like Cisco are caught only
// via product terms below, to keep enterprise CVE noise out).
const TELCO_VENDOR =
    'ericsson|nokia|mavenir|\\mzte\\M|casa systems|athonet|affirmed|ribbon communic|metaswitch|oracle communications|open5gs|srsran|samsung.*baseband';

export async function telcoIntel(limit = 80): Promise<TelcoIntelItem[]> {
    const cap = Math.min(limit, 200);

    const pulseRows = await db.execute(sql`
        SELECT otx_id, name, tlp, tags, otx_modified, created_at
        FROM pulses
        WHERE name ~* ${TELCO_KW}
           OR COALESCE(description, '') ~* ${TELCO_KW}
           OR COALESCE(adversary, '') ~* ${TELCO_KW}
           OR EXISTS (SELECT 1 FROM unnest(tags) tg WHERE tg ~* ${TELCO_KW})
        ORDER BY created_at DESC
        LIMIT ${cap}
    `) as unknown as Array<{ otx_id: string; name: string; tlp: string | null; tags: string[] | null; otx_modified: string | null; created_at: string | null }>;

    const cveRows = await db.execute(sql`
        SELECT cve_id, severity, vendor_project, product, published_date, created_at
        FROM vulnerabilities
        WHERE vendor_project ~* ${TELCO_VENDOR}
           OR COALESCE(product, '') ~* ${TELCO_KW}
        ORDER BY created_at DESC
        LIMIT ${cap}
    `) as unknown as Array<{ cve_id: string; severity: string | null; vendor_project: string | null; product: string | null; published_date: string | null; created_at: string | null }>;

    const items: TelcoIntelItem[] = [
        ...pulseRows.map((p): TelcoIntelItem => ({
            kind: 'pulse',
            id: p.otx_id,
            title: p.name,
            ref: `https://otx.alienvault.com/pulse/${p.otx_id}`,
            severity: (p.tlp ?? '').toLowerCase() === 'red' ? 'critical' : (p.tlp ?? '').toLowerCase() === 'amber' ? 'high' : null,
            tags: p.tags ?? [],
            date: p.otx_modified,
            added: p.created_at,
            source: 'otx',
        })),
        ...cveRows.map((v): TelcoIntelItem => ({
            kind: 'cve',
            id: v.cve_id,
            title: [v.vendor_project, v.product].filter(Boolean).join(' · ') || v.cve_id,
            ref: `https://nvd.nist.gov/vuln/detail/${v.cve_id}`,
            severity: v.severity,
            tags: [v.vendor_project, v.product].filter((x): x is string => !!x),
            date: v.published_date,
            added: v.created_at,
            source: 'cve',
        })),
    ];

    // Unified recency order by ingestion (the "Added" signal), newest first.
    items.sort((a, b) => (b.added ?? '').localeCompare(a.added ?? ''));
    return items.slice(0, cap);
}
