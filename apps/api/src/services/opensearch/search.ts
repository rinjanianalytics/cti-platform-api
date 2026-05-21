/**
 * OpenSearch Unified Search — Full-text + Faceted Search
 */

import { getOpenSearchClient, INDICES } from './client';

// ============================================================================
// OpenSearch Response Types
// ============================================================================

interface OSHit {
    _id: string;
    _score: number | null;
    _source: Record<string, unknown>;
}

interface OSBucket {
    key: string;
    doc_count: number;
    [nested: string]: unknown;
}

// ============================================================================
// Single Document Lookup
// ============================================================================

/**
 * Get a single document by ID or value
 * Searches both the `id` field (for UUIDs) and `value` field
 */
export async function getById(
    idOrValue: string,
    entityType?: 'ioc' | 'vulnerability' | 'actor'
): Promise<{ item: Record<string, unknown> | null; took: number }> {
    const client = getOpenSearchClient();

    const filter: Record<string, unknown>[] = [];
    if (entityType) {
        filter.push({ term: { 'entityType.keyword': entityType } });
    }

    // Search by both id (keyword exact match) and value
    const searchBody: Record<string, unknown> = {
        query: {
            bool: {
                filter,
                should: [
                    { term: { 'id.keyword': idOrValue } },  // Exact match on id field (keyword sub-field)
                    { match: { value: { query: idOrValue, operator: 'and' } } },  // Match on value
                ],
                minimum_should_match: 1,
            },
        },
        _source: { excludes: ['embedding'] },
        size: 1,
    };

    try {
        const response = await client.search({
            index: INDICES.unified,
            body: searchBody,
        });

        const hits = response.body.hits.hits;
        return {
            item: hits.length > 0 ? hits[0]._source : null,
            took: response.body.took,
        };
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) {
            return { item: null, took: 0 };
        }
        throw error;
    }
}

// ============================================================================
// Unified Search
// ============================================================================

export interface SearchOptions {
    query: string;
    filters?: {
        entityType?: string[];
        /** IOC type (`ip`, `domain`, `url`, `hash`, `email`, `cve`, …) */
        type?: string[];
        severity?: string[];
        source?: string[];
        dateFrom?: string;
        dateTo?: string;
    };
    sort?: { field: string; order: 'asc' | 'desc' };
    pagination?: { page: number; limit: number };
    aggregations?: boolean;
}

export interface SearchResult {
    items: Record<string, unknown>[];
    total: number;
    facets?: {
        entityType: Record<string, number>;
        severity: Record<string, number>;
        source: Record<string, number>;
    };
    took: number;
}

export async function unifiedSearch(options: SearchOptions): Promise<SearchResult> {
    const client = getOpenSearchClient();

    const {
        query,
        filters = {},
        sort = { field: 'updatedAt', order: 'desc' },
        pagination = { page: 1, limit: 25 },
        aggregations = true,
    } = options;

    // Build query
    const must: Record<string, unknown>[] = [];
    const should: Record<string, unknown>[] = [];
    const filter: Record<string, unknown>[] = [];

    // Full-text search
    if (query && query.trim()) {
        const q = query.trim();

        // Detect if query looks like a structured identifier (CVE, IP, hash, domain, URL)
        const isCVE = /^CVE-\d{4}-\d+$/i.test(q);
        const isPartialCVE = /^CVE-\d{4}/i.test(q);
        const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q);
        const isHash = /^[a-f0-9]{32,64}$/i.test(q);
        const isDomain = /^(?!-)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/i.test(q) && !q.includes('/');
        const isURL = /^https?:\/\//i.test(q);
        const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q);
        const isStructured = isCVE || isIP || isHash || isDomain || isURL || isEmail;

        if (isStructured) {
            // Exact match for structured identifiers - use match (analyzed, case-insensitive)
            must.push({
                match: {
                    value: {
                        query: q,
                        operator: 'and',
                    },
                },
            });
        } else if (isPartialCVE) {
            // Prefix match for partial CVE-2024 style queries
            must.push({
                match_phrase_prefix: {
                    value: q,
                },
            });
        } else {
            // General fuzzy search for text queries
            must.push({
                multi_match: {
                    query: q,
                    fields: ['value^3', 'title^2', 'description', 'tags'],
                    type: 'best_fields',
                    fuzziness: 'AUTO',
                },
            });
        }
    } else {
        must.push({ match_all: {} });
    }

    // Filters
    if (filters.entityType?.length) {
        filter.push({ terms: { 'entityType.keyword': filters.entityType } });
    }
    if (filters.type?.length) {
        filter.push({ terms: { 'type.keyword': filters.type } });
    }
    if (filters.severity?.length) {
        filter.push({ terms: { 'severity.keyword': filters.severity } });
    }
    if (filters.source?.length) {
        filter.push({ terms: { 'source.keyword': filters.source } });
    }
    if (filters.dateFrom || filters.dateTo) {
        const range: Record<string, Record<string, string>> = { updatedAt: {} };
        if (filters.dateFrom) range.updatedAt.gte = filters.dateFrom;
        if (filters.dateTo) range.updatedAt.lte = filters.dateTo;
        filter.push({ range });
    }

    // Build search body
    const searchBody: Record<string, unknown> = {
        query: {
            bool: {
                must,
                filter,
            },
        },
        _source: { excludes: ['embedding'] },
        from: (pagination.page - 1) * pagination.limit,
        size: pagination.limit,
    };

    // Only add explicit sort when NOT sorting by relevance (_score)
    // Omitting sort lets OpenSearch use native relevance ranking
    if (sort.field !== '_score') {
        searchBody.sort = [{ [sort.field]: sort.order }];
    }

    // Add aggregations
    if (aggregations) {
        searchBody.aggs = {
            entityType: { terms: { field: 'entityType.keyword', size: 10 } },
            severity: { terms: { field: 'severity.keyword', size: 10 } },
            source: { terms: { field: 'source.keyword', size: 20 } },
        };
    }

    try {
        const response = await client.search({
            index: INDICES.unified,
            body: searchBody,
        });

        const hits = response.body.hits;
        const items = hits.hits.map((hit: OSHit) => ({
            _score: hit._score,
            ...hit._source,
        }));

        // Parse facets
        let facets = undefined;
        if (aggregations && response.body.aggregations) {
            facets = {
                entityType: Object.fromEntries(
                    response.body.aggregations.entityType.buckets.map((b: OSBucket) => [b.key, b.doc_count])
                ),
                severity: Object.fromEntries(
                    response.body.aggregations.severity.buckets.map((b: OSBucket) => [b.key, b.doc_count])
                ),
                source: Object.fromEntries(
                    response.body.aggregations.source.buckets.map((b: OSBucket) => [b.key, b.doc_count])
                ),
            };
        }

        return {
            items,
            total: typeof hits.total === 'number' ? hits.total : hits.total.value,
            facets,
            took: response.body.took,
        };
    } catch (error) {
        // If index doesn't exist, return empty results
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) {
            return { items: [], total: 0, took: 0 };
        }
        throw error;
    }
}
