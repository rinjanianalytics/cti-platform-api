/**
 * Advanced Search Zod Schemas
 */

import { z } from 'zod';

const MAX_PAGE_SIZE = 500;

export const PaginationSchema = z.object({
    page: z.number().int().min(1).default(1),
    limit: z.number().int().min(1).max(MAX_PAGE_SIZE).default(100),
});

export const SortSchema = z.object({
    field: z.string().default('lastSeen'),
    order: z.enum(['asc', 'desc']).default('desc'),
});

export const IOCSearchSchema = z.object({
    query: z.string().max(500).default(''),
    filters: z.object({
        type: z.array(z.string()).optional(),
        source: z.array(z.string()).optional(),
        severity: z.array(z.string()).optional(),
        threatType: z.string().optional(),
        minConfidence: z.number().int().min(0).max(100).optional(),
        maxConfidence: z.number().int().min(0).max(100).optional(),
        dateFrom: z.string().datetime().optional(),
        dateTo: z.string().datetime().optional(),
    }).prefault({}),
    sort: SortSchema.prefault({}),
    pagination: PaginationSchema.prefault({}),
    aggregations: z.boolean().default(false),
});

export const VulnSearchSchema = z.object({
    query: z.string().max(500).default(''),
    filters: z.object({
        severity: z.array(z.string()).optional(),
        exploited: z.boolean().optional(),
        minCvss: z.number().min(0).max(10).optional(),
        maxCvss: z.number().min(0).max(10).optional(),
        dateFrom: z.string().datetime().optional(),
        dateTo: z.string().datetime().optional(),
        vendor: z.string().optional(),
    }).prefault({}),
    sort: SortSchema.default({ field: 'publishedDate', order: 'desc' }),
    pagination: PaginationSchema.default({ page: 1, limit: 50 }),
});
