/**
 * Engine-backed feed handler — A3 of the declarative connector engine.
 *
 * Wraps the pure @rinjani/feed-engine in the three side-effects it doesn't
 * do itself: HTTP fetch, IOC sink (drizzle upsert), and SyncResult shape so
 * the BullMQ worker downstream (auto-enrichment FlowProducer at
 * feedSyncWorker.ts:176) is unchanged.
 *
 * Scope for A3: IOC entity only. The seed engine in @rinjani/feed-engine is
 * IOC-only too; non-IOC manifests are filtered out at resolveFeedHandler()
 * before they reach this module. A4+ widen the sink.
 */

import { db, eq } from '@rinjani/db';
import { iocs, feedManifest } from '@rinjani/db/schema';
import { runEngine, type FeedManifest, type CanonicalIoc } from '@rinjani/feed-engine';
import type { FeedHandler, FeedSyncOptions } from './feedRegistry';
import type { SyncResult } from './types';
import { createLogger } from '../../lib/logger';

const log = createLogger('EngineHandler');

/**
 * Fetch a feed payload per the manifest's source spec. Supports the auth
 * shapes the seed manifest schema allows: none, bearer (token from env via
 * `header` field), apiKeyHeader (literal token in env, header name from
 * `header` field). Auth secrets come from env vars referenced by name —
 * never embedded in the manifest body.
 */
async function fetchPayload(manifest: FeedManifest): Promise<string> {
    const { url, method, headers, auth, body } = manifest.source;

    const reqHeaders: Record<string, string> = { ...headers };
    if (auth.type === 'bearer' && auth.header) {
        const token = process.env[auth.header];
        if (token) reqHeaders['Authorization'] = `Bearer ${token}`;
    } else if (auth.type === 'apiKeyHeader' && auth.header) {
        // For apiKeyHeader, the manifest `header` field carries the header NAME
        // (e.g. "Auth-Key" for abuse.ch). The secret value comes from the env
        // var of the same name — manifests never embed credentials.
        const token = process.env[auth.header];
        if (token) reqHeaders[auth.header] = token;
    }

    const init: RequestInit = { method, headers: reqHeaders };
    if (body !== undefined && method === 'POST') {
        if (typeof body === 'string') {
            init.body = body;
        } else {
            init.body = JSON.stringify(body);
            if (!reqHeaders['Content-Type'] && !reqHeaders['content-type']) {
                reqHeaders['Content-Type'] = 'application/json';
            }
        }
    }

    const response = await fetch(url, init);
    if (!response.ok) {
        throw new Error(`Engine feed fetch failed: ${response.status} ${response.statusText} (${url})`);
    }
    return response.text();
}

/**
 * IOC sink — upserts engine output into the `iocs` table.
 * Mirrors the upsert pattern in apps/worker/src/feeds/abusessl.ts so behaviour
 * is identical to legacy feed handlers from the perspective of downstream
 * enrichment + decay machinery.
 *
 * Per-record errors are collected; sink continues on row failures (matches
 * legacy handler behaviour). Caller routes errors into SyncResult.errors[].
 */
async function iocSink(records: CanonicalIoc[]): Promise<{
    added: number;
    updated: number;
    errors: string[];
    indicators: Array<{ id: string; value: string; type: string }>;
}> {
    const indicators: Array<{ id: string; value: string; type: string }> = [];
    const errors: string[] = [];
    let added = 0;
    let updated = 0;

    for (const rec of records) {
        try {
            const row = {
                type: rec.type,
                value: rec.value,
                source: rec.source,
                threatType: rec.threatType ?? null,
                confidence: rec.confidence ?? null,
                severity: rec.severity ?? null,
                tags: rec.tags ?? [],
                pulseId: rec.pulseId ?? null,
                firstSeen: rec.firstSeen ? new Date(rec.firstSeen) : null,
                lastSeen: rec.lastSeen ? new Date(rec.lastSeen) : new Date(),
            };

            const existing = await db
                .select({ id: iocs.id })
                .from(iocs)
                .where(eq(iocs.value, rec.value))
                .limit(1);

            if (existing[0]) {
                await db
                    .update(iocs)
                    .set({ ...row, updatedAt: new Date() })
                    .where(eq(iocs.id, existing[0].id));
                updated++;
                indicators.push({ id: existing[0].id, value: rec.value, type: rec.type });
            } else {
                const [inserted] = await db.insert(iocs).values(row).returning({ id: iocs.id });
                added++;
                indicators.push({ id: inserted.id, value: rec.value, type: rec.type });
            }
        } catch (err) {
            if (errors.length < 10) {
                errors.push(`IOC ${rec.value}: ${(err as Error).message}`);
            }
        }
    }

    return { added, updated, errors, indicators };
}

/**
 * Build a FeedHandler closure for one active manifest. The returned handler
 * matches the legacy FeedHandler signature exactly so it slots into the
 * dispatch path with no worker changes.
 *
 * Stamps `last_validated_at` on the manifest row after a successful run, so
 * the dashboard can show "last verified-working" timestamps even when the
 * legacy fallback is what's actually running.
 */
export function buildEngineHandler(manifest: FeedManifest, manifestRowId: string): FeedHandler {
    return async (_opts?: FeedSyncOptions): Promise<SyncResult> => {
        const errors: string[] = [];
        try {
            const payload = await fetchPayload(manifest);

            const result = runEngine(manifest as FeedManifest & { entity: 'ioc' }, payload);

            log.info('Engine ran', {
                source: manifest.id,
                read: result.stats.read,
                ok: result.stats.ok,
                failed: result.stats.failed,
            });

            // Engine per-record parse errors land in the same SyncResult.errors[]
            // surface the legacy handlers use.
            for (const e of result.errors.slice(0, 10)) {
                errors.push(`record[${e.index}]: ${e.reason}`);
            }

            // Sink to iocs table. Records here are CanonicalIoc since A3 is
            // IOC-only (non-IOC manifests are filtered before this point).
            const sink = await iocSink(result.records as CanonicalIoc[]);
            errors.push(...sink.errors);

            // Stamp last_validated_at — best-effort, never fails the sync.
            try {
                await db
                    .update(feedManifest)
                    .set({ lastValidatedAt: new Date(), lastValidationErrors: errors.length > 0 ? errors : null })
                    .where(eq(feedManifest.id, manifestRowId));
            } catch (err) {
                log.warn('Failed to stamp last_validated_at', { error: (err as Error).message });
            }

            return {
                success: sink.errors.length === 0 || sink.added + sink.updated > 0,
                pulsesProcessed: 1,
                indicatorsProcessed: result.stats.read,
                indicatorsAdded: sink.added,
                indicatorsUpdated: sink.updated,
                errors,
                indicators: sink.indicators,
            };
        } catch (err) {
            const msg = (err as Error).message;
            log.error('Engine handler failed', err as Error, { source: manifest.id });
            return {
                success: false,
                pulsesProcessed: 0,
                indicatorsProcessed: 0,
                indicatorsAdded: 0,
                indicatorsUpdated: 0,
                errors: [msg, ...errors],
            };
        }
    };
}
