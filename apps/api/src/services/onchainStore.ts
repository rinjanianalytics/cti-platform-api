/**
 * On-chain entity store — AA.6.1 CRUD for the wallets table.
 *
 * Operator-entered, feed-ingested (OFAC/ScamSniffer/DefiLlama), or enriched
 * via the free multi-source on-chain lookup. Create is an idempotent
 * upsert on the natural key `ref_id` ("<chain>:<address>"), mirroring the telco
 * store. Pure relational CRUD — wallets become graph-participating only when
 * fund-flow relationships referencing them are inserted (AA.6.2).
 */

import { db, eq, desc, ilike, and, sql } from '@rinjani/db';
import { wallets } from '@rinjani/db/schema';
import type { Wallet, NewWallet } from '@rinjani/db/schema';

export async function upsertWallet(data: NewWallet): Promise<Wallet> {
    const [row] = await db
        .insert(wallets)
        .values(data)
        .onConflictDoUpdate({
            target: wallets.refId,
            set: { ...data, updatedAt: new Date() },
        })
        .returning();
    return row;
}

export async function listWallets(filters: {
    chain?: string;
    entityType?: string;
    q?: string;
    /** JSONB containment on risk_tags: `risk_tags @> '["mixer"]'`. */
    riskTag?: string;
    limit?: number;
} = {}): Promise<Wallet[]> {
    const conds = [];
    if (filters.chain) conds.push(eq(wallets.chain, filters.chain));
    if (filters.entityType) conds.push(eq(wallets.entityType, filters.entityType));
    if (filters.q) conds.push(ilike(wallets.entityLabel, `%${filters.q}%`));
    if (filters.riskTag) {
        conds.push(sql`${wallets.riskTags} @> ${JSON.stringify([filters.riskTag])}::jsonb`);
    }
    return db
        .select()
        .from(wallets)
        .where(conds.length ? and(...conds) : undefined)
        .orderBy(desc(wallets.createdAt))
        .limit(Math.min(filters.limit ?? 100, 500));
}

export async function getWallet(id: string): Promise<Wallet | null> {
    const rows = await db.select().from(wallets).where(eq(wallets.id, id)).limit(1);
    return rows[0] ?? null;
}

/** Look up a wallet by its natural key "<chain>:<address>". Used by the
 *  free on-chain attribution aggregator to resolve DB-first (OFAC sanctioned,
 *  ScamSniffer scam, analyst-curated) before hitting external sources. */
export async function getWalletByRef(refId: string): Promise<Wallet | null> {
    const rows = await db.select().from(wallets).where(eq(wallets.refId, refId)).limit(1);
    return rows[0] ?? null;
}

export async function deleteWallet(id: string): Promise<boolean> {
    const out = await db.delete(wallets).where(eq(wallets.id, id)).returning({ id: wallets.id });
    return out.length > 0;
}

export interface WalletStats {
    total: number;
    /** Counts by entity_type (sanctioned, scam, defi, …). */
    byType: Record<string, number>;
    /** Counts by attribution_source (ofac, scamsniffer, defillama, …). */
    bySource: Record<string, number>;
}

/**
 * Category counts via GROUP BY — the REST list caps at 500 rows, so the
 * dashboard cannot derive accurate per-category totals (scam alone is ~2.5k).
 * These aggregates come straight from Postgres and are cheap.
 */
export async function walletStats(): Promise<WalletStats> {
    const [typeRows, sourceRows, totalRow] = await Promise.all([
        db.select({ k: wallets.entityType, n: sql<number>`count(*)::int` })
            .from(wallets).groupBy(wallets.entityType),
        db.select({ k: wallets.attributionSource, n: sql<number>`count(*)::int` })
            .from(wallets).groupBy(wallets.attributionSource),
        db.select({ n: sql<number>`count(*)::int` }).from(wallets),
    ]);
    const toMap = (rows: Array<{ k: string | null; n: number }>) =>
        Object.fromEntries(rows.filter((r) => r.k).map((r) => [r.k as string, Number(r.n)]));
    return {
        total: Number(totalRow[0]?.n ?? 0),
        byType: toMap(typeRows),
        bySource: toMap(sourceRows),
    };
}
