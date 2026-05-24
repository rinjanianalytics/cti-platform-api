/**
 * Shared helpers for v1 sub-routes.
 *
 * NOTE: `paginate()` is the canonical pagination shape for every list
 * endpoint — `{page, pageSize, total, pages}`. The previous shape
 * `{totalItems, totalPages}` forced client-side coercion and is gone.
 * Add new list endpoints by calling `paginate()` exactly once. For more
 * structured pagination (typed `PaginatedList<T>`), use the DTO helper:
 *   import { toPaginated } from '../../dto';
 */

import { buildPagination, type Pagination } from '../../dto/pagination';

export function paginate(page: number, pageSize: number, total: number): Pagination {
    return buildPagination(page, pageSize, total);
}
