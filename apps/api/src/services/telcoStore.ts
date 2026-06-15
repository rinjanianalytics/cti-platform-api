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
