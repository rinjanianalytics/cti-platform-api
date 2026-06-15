/**
 * Connector (feed manifest) store — CRUD + activation transitions.
 *
 * Backs /v1/connectors/*. Manifests are immutable: every "save" creates a new
 * row with version = max(version) + 1 for the source. Activation flips the
 * is_active flag in a single transaction so the (source) WHERE is_active
 * partial unique index can never observe two active rows for one source.
 */

import { db, eq, and, desc, sql } from '@rinjani/db';
import { feedManifest } from '@rinjani/db/schema';
import type { FeedManifestRow, NewFeedManifestRow } from '@rinjani/db/schema';
import { FeedManifest as FeedManifestSchema } from '@rinjani/feed-engine';

export interface CreateManifestInput {
    source: string;
    entity: string;
    manifest: Record<string, unknown>;
    createdBy: string;
}

export interface ListFilters {
    source?: string;
    entity?: string;
    activeOnly?: boolean;
}

/**
 * Validate a manifest body against the engine's zod schema.
 * Returns the parsed object on success; the engine accepts this object directly.
 */
export function validateManifestBody(body: unknown): { ok: true; data: Record<string, unknown> } | { ok: false; errors: Array<{ path: string; message: string }> } {
    const parsed = FeedManifestSchema.safeParse(body);
    if (parsed.success) return { ok: true, data: parsed.data as Record<string, unknown> };
    return {
        ok: false,
        errors: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    };
}

/**
 * Create a new manifest version. Version is server-assigned: max(version) + 1
 * for the source, starting at 1.
 *
 * Throws if the source/entity combination conflicts with an existing source
 * that uses a different entity (one source = one entity for the engine).
 */
export async function createManifest(input: CreateManifestInput): Promise<FeedManifestRow> {
    const [{ nextVersion }] = await db.execute(sql<{ nextVersion: number }>`
        SELECT COALESCE(MAX(version), 0) + 1 AS "nextVersion"
        FROM feed_manifest
        WHERE source = ${input.source}
    `) as unknown as [{ nextVersion: number }];

    const existing = await db
        .select({ entity: feedManifest.entity })
        .from(feedManifest)
        .where(eq(feedManifest.source, input.source))
        .limit(1);
    if (existing[0] && existing[0].entity !== input.entity) {
        throw new ConnectorConflictError(
            `source '${input.source}' already uses entity '${existing[0].entity}'; cannot save as '${input.entity}'`,
        );
    }

    const row: NewFeedManifestRow = {
        source: input.source,
        version: nextVersion,
        entity: input.entity,
        manifest: input.manifest,
        isActive: false,
        createdBy: input.createdBy,
    };

    const [created] = await db.insert(feedManifest).values(row).returning();
    return created;
}

export async function getById(id: string): Promise<FeedManifestRow | null> {
    const rows = await db.select().from(feedManifest).where(eq(feedManifest.id, id)).limit(1);
    return rows[0] ?? null;
}

export async function listManifests(filters: ListFilters = {}): Promise<FeedManifestRow[]> {
    const conditions = [];
    if (filters.source) conditions.push(eq(feedManifest.source, filters.source));
    if (filters.entity) conditions.push(eq(feedManifest.entity, filters.entity));
    if (filters.activeOnly) conditions.push(eq(feedManifest.isActive, true));

    const where = conditions.length === 0 ? undefined
        : conditions.length === 1 ? conditions[0]
        : and(...conditions);

    return db
        .select()
        .from(feedManifest)
        .where(where)
        .orderBy(desc(feedManifest.createdAt));
}

/**
 * Activate one version; deactivate any currently-active version for the same
 * source. Wrapped in a transaction so the partial unique index never sees
 * two active rows.
 *
 * Returns the activated row, or null if the id doesn't exist.
 */
export async function activate(id: string): Promise<FeedManifestRow | null> {
    return db.transaction(async (tx) => {
        const target = await tx
            .select()
            .from(feedManifest)
            .where(eq(feedManifest.id, id))
            .limit(1);
        if (!target[0]) return null;
        const { source } = target[0];

        await tx
            .update(feedManifest)
            .set({ isActive: false })
            .where(and(eq(feedManifest.source, source), eq(feedManifest.isActive, true)));

        const [activated] = await tx
            .update(feedManifest)
            .set({ isActive: true })
            .where(eq(feedManifest.id, id))
            .returning();

        return activated ?? null;
    });
}

/**
 * Soft-delete: clear is_active. Rows are immutable so we never DROP.
 * Idempotent.
 */
export async function deactivate(id: string): Promise<FeedManifestRow | null> {
    const [updated] = await db
        .update(feedManifest)
        .set({ isActive: false })
        .where(eq(feedManifest.id, id))
        .returning();
    return updated ?? null;
}

export class ConnectorConflictError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'ConnectorConflictError';
    }
}
