/**
 * Canonical pagination envelope.
 *
 * Returned by every list endpoint. The client previously had a
 * `normalisePagination()` shim because the backend was split between
 * `{totalItems, totalPages}` and `{total, pages}` — this shape is the
 * single source of truth going forward.
 *
 * Field choice rationale: `total` (rows in the result set) + `pages`
 * (count of pages) is the shorter, more conventional shape. Existing
 * `paginate()` helper in `routes/v1/helpers.ts` re-exports `toPaginated`.
 */

export interface Pagination {
    page: number;
    pageSize: number;
    total: number;
    pages: number;
}

export interface PaginatedList<T> {
    items: T[];
    pagination: Pagination;
}

/** Build a Pagination from raw inputs. */
export function buildPagination(page: number, pageSize: number, total: number): Pagination {
    const safeSize = Math.max(1, pageSize | 0);
    return {
        page: Math.max(1, page | 0),
        pageSize: safeSize,
        total: Math.max(0, total | 0),
        pages: Math.max(0, Math.ceil(total / safeSize)),
    };
}

/** Wrap a (already-shaped) row array into a list response. */
export function toPaginated<T>(
    items: T[],
    opts: { page: number; pageSize: number; total: number },
): PaginatedList<T> {
    return {
        items,
        pagination: buildPagination(opts.page, opts.pageSize, opts.total),
    };
}
