/**
 * Connector preview + test services — A6 backend support.
 *
 * Pure compute (no DB, no LLM, no network). The route handlers in
 * routes/v1/connectors.ts are thin wrappers around these — tests target
 * the functions directly so we don't need a full HTTP harness.
 *
 *   previewExtract: given a sample + extract config, return raw records.
 *                   No manifest required. Used by the UI for field discovery.
 *   testManifest:   given a sample + a complete manifest, run the engine
 *                   and return dry-run stats + canonical records.
 */

import {
    FeedManifest as FeedManifestSchema,
    extractRecords,
    runEngine,
} from '@rinjani/feed-engine';
import type { FeedManifest } from '@rinjani/feed-engine';

export interface PreviewInput {
    sample: string;
    format: 'json' | 'csv' | 'text';
    recordsPath?: string;
    csv?: { delimiter: string; hasHeader: boolean };
    text?: { commentPrefix: string };
    limit: number;
}

export interface PreviewResult {
    ok: boolean;
    records: Record<string, unknown>[];
    fields: string[];
    totalCount: number;
    reason?: string;
}

export function previewExtract(input: PreviewInput): PreviewResult {
    // Build a stub manifest carrying only the extract config the engine cares
    // about. `mapping: {}` is fine — extractRecords doesn't read it.
    let stubManifest: FeedManifest;
    try {
        stubManifest = FeedManifestSchema.parse({
            id: 'preview',
            name: 'preview',
            entity: 'ioc',
            source: {
                url: 'https://preview.invalid',
                method: 'GET',
                headers: {},
                auth: { type: 'none' },
            },
            format: input.format,
            extract: { recordsPath: input.recordsPath, csv: input.csv, text: input.text },
            mapping: {},
        });
    } catch (err) {
        return { ok: false, records: [], fields: [], totalCount: 0, reason: (err as Error).message };
    }

    let records: Record<string, unknown>[];
    try {
        records = extractRecords(stubManifest, input.sample);
    } catch (err) {
        return { ok: false, records: [], fields: [], totalCount: 0, reason: (err as Error).message };
    }

    // Discover the union of top-level field names across the first 50 records
    // so the UI can render a field-map table even on heterogeneous payloads.
    const fields = new Set<string>();
    for (const r of records.slice(0, Math.min(50, records.length))) {
        if (r && typeof r === 'object') {
            for (const k of Object.keys(r)) fields.add(k);
        }
    }

    return {
        ok: true,
        records: records.slice(0, input.limit),
        fields: Array.from(fields).sort(),
        totalCount: records.length,
    };
}

export interface TestInput {
    manifest: unknown;
    sample: string;
    limit: number;
}

export interface TestResult {
    ok: boolean;
    dryRun?: {
        read: number;
        ok: number;
        failed: number;
        errors: Array<{ index: number; reason: string }>;
    };
    records?: unknown[];
    validationIssues?: Array<{ path: string; message: string }>;
    runtimeError?: string;
}

export function testManifest(input: TestInput): TestResult {
    const validated = FeedManifestSchema.safeParse(input.manifest);
    if (!validated.success) {
        return {
            ok: false,
            validationIssues: validated.error.issues.map((i) => ({
                path: i.path.join('.'),
                message: i.message,
            })),
        };
    }

    let dryRun: ReturnType<typeof runEngine>;
    try {
        dryRun = runEngine(
            validated.data as FeedManifest & { entity: typeof validated.data.entity },
            input.sample,
        );
    } catch (err) {
        return { ok: false, runtimeError: (err as Error).message };
    }

    return {
        ok: true,
        dryRun: {
            read: dryRun.stats.read,
            ok: dryRun.stats.ok,
            failed: dryRun.stats.failed,
            errors: dryRun.errors.slice(0, 10),
        },
        records: dryRun.records.slice(0, input.limit),
    };
}
