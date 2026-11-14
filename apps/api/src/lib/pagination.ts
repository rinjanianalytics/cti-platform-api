/**
 * Cursor-Based Pagination — Shared Helper
 *
 * Replaces offset pagination (O(n) skip) with cursor-based (O(1) seek).
 * Uses the composite key [timestamp, id] for stable, deterministic ordering.
 *
 * Usage (Drizzle ORM):
 *   const { cursor, limit } = parseCursorParams(c.req.query());
 *   const rows = await db.select()
 *     .from(iocs)
 *     .where(cursor ? and(lt(iocs.createdAt, cursor.timestamp), lt(iocs.id, cursor.id)) : undefined)
 *     .orderBy(desc(iocs.createdAt), desc(iocs.id))
 *     .limit(limit + 1);
 *   return buildCursorResponse(rows, limit, row => ({
 *     timestamp: row.createdAt,
 *     id: row.id,
 *   }));
 */

import { z } from 'zod';

// ============================================================================
// Types
// ============================================================================

export interface CursorToken {
    timestamp: string;
    id: string;
}

export interface CursorPaginatedResponse<T> {
    data: T[];
    pagination: {
        limit: number;
        hasMore: boolean;
        nextCursor: string | null;
        prevCursor: string | null;
    };
}

// ============================================================================
// Zod Schema for cursor query params
// ============================================================================

export const CursorParamsSchema = z.object({
    cursor: z.string().optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    direction: z.enum(['next', 'prev']).default('next'),
});

// ============================================================================
// Shared validation schemas
// ============================================================================

export const IdParamSchema = z.object({
    id: z.string().guid('Invalid UUID format'),
});

export const PaginationSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(200).default(50),
});

export const DateRangeSchema = z.object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
});

export const SortSchema = z.object({
    sortBy: z.string().default('createdAt'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Encode a cursor token to a base64 string
 */
export function encodeCursor(token: CursorToken): string {
    return Buffer.from(JSON.stringify(token)).toString('base64url');
}

/**
 * Decode a cursor string back to a token
 */
export function decodeCursor(cursor: string): CursorToken | null {
    try {
        const decoded = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf-8'));
        if (decoded.timestamp && decoded.id) {
            return decoded as CursorToken;
        }
    } catch {
        // Invalid cursor
    }
    return null;
}

/**
 * Parse cursor pagination params from query string
 */
export function parseCursorParams(query: Record<string, string | undefined>) {
    const parsed = CursorParamsSchema.parse(query);
    return {
        cursor: parsed.cursor ? decodeCursor(parsed.cursor) : null,
        limit: parsed.limit,
        direction: parsed.direction,
    };
}

/**
 * Build a cursor-paginated response from a query result.
 *
 * Fetch `limit + 1` rows. If we get more than `limit`, there's a next page.
 * The cursor extractor function maps a row to its cursor token.
 */
export function buildCursorResponse<T>(
    rows: T[],
    limit: number,
    cursorExtractor: (row: T) => CursorToken,
): CursorPaginatedResponse<T> {
    const hasMore = rows.length > limit;
    const data = hasMore ? rows.slice(0, limit) : rows;

    const nextCursor = hasMore && data.length > 0
        ? encodeCursor(cursorExtractor(data[data.length - 1]))
        : null;

    const prevCursor = data.length > 0
        ? encodeCursor(cursorExtractor(data[0]))
        : null;

    return {
        data,
        pagination: {
            limit,
            hasMore,
            nextCursor,
            prevCursor,
        },
    };
}
