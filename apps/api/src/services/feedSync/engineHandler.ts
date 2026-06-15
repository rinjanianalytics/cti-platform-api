/**
 * Engine-backed feed handler — A3 of the declarative connector engine,
 * widened to vulnerability sink in A7.1.
 *
 * Wraps the pure @rinjani/feed-engine in the three side-effects it doesn't
 * do itself: HTTP fetch, entity-specific sink (drizzle upsert), and
 * SyncResult shape so the BullMQ worker downstream (auto-enrichment
 * FlowProducer at feedSyncWorker.ts:176) is unchanged.
 *
 * Supported entities (A7.1): ioc, vulnerability. The dispatch in
 * buildEngineHandler chooses the right sink. resolveFeedHandler() in
 * feedRegistry.ts gates the allowed set — extending support there is what
 * each future A7.N migration does.
 */

import { db, eq } from '@rinjani/db';
import { iocs, vulnerabilities, feedManifest } from '@rinjani/db/schema';
import { runEngine, type FeedManifest, type CanonicalIoc, type CanonicalVulnerability } from '@rinjani/feed-engine';
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
 * Vulnerability sink (A7.1) — upserts engine output into the `vulnerabilities`
 * table. Mirrors the upsert pattern in apps/api/src/services/feedSync/cisaSync.ts
 * so legacy CISA handler behavior carries through unchanged: KEV rows always
 * carry isExploited=true (legacy did this implicitly; the manifest now does it
 * explicitly via `{literal: true}`).
 *
 * Per-record errors collected; continues on row failures (matches legacy +
 * iocSink semantics).
 */
async function vulnerabilitySink(records: CanonicalVulnerability[]): Promise<{
    added: number;
    updated: number;
    errors: string[];
}> {
    const errors: string[] = [];
    let added = 0;
    let updated = 0;

    for (const rec of records) {
        try {
            const row = {
                cveId: rec.cveId,
                description: rec.description ?? null,
                cvssScore: rec.cvssScore !== undefined ? String(rec.cvssScore) : null,
                cvssVector: rec.cvssVector ?? null,
                severity: rec.severity ?? null,
                cweId: rec.cweId ?? null,
                isExploited: rec.isExploited ?? false,
                // Date columns in PG accept YYYY-MM-DD strings directly; the
                // engine emits them in that shape so no Date() coercion needed.
                exploitAddedDate: rec.exploitAddedDate ?? null,
                dueDate: rec.dueDate ?? null,
                epssScore: rec.epssScore !== undefined ? String(rec.epssScore) : null,
                epssPercentile: rec.epssPercentile !== undefined ? String(rec.epssPercentile) : null,
                vendorProject: rec.vendorProject ?? null,
                product: rec.product ?? null,
                references: rec.references ?? [],
                publishedDate: rec.publishedDate ? new Date(rec.publishedDate) : null,
                lastModified: rec.lastModified ? new Date(rec.lastModified) : null,
                syncedAt: new Date(),
            };

            const existing = await db
                .select({ id: vulnerabilities.id })
                .from(vulnerabilities)
                .where(eq(vulnerabilities.cveId, rec.cveId))
                .limit(1);

            if (existing[0]) {
                await db
                    .update(vulnerabilities)
                    .set({ ...row, updatedAt: new Date() })
                    .where(eq(vulnerabilities.id, existing[0].id));
                updated++;
            } else {
                await db.insert(vulnerabilities).values(row);
                added++;
            }
        } catch (err) {
            if (errors.length < 10) {
                errors.push(`CVE ${rec.cveId}: ${(err as Error).message}`);
            }
        }
    }

    return { added, updated, errors };
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

            const result = runEngine(manifest, payload);

            log.info('Engine ran', {
                source: manifest.id,
                entity: manifest.entity,
                read: result.stats.read,
                ok: result.stats.ok,
                failed: result.stats.failed,
            });

            // Engine per-record parse errors land in the same SyncResult.errors[]
            // surface the legacy handlers use.
            for (const e of result.errors.slice(0, 10)) {
                errors.push(`record[${e.index}]: ${e.reason}`);
            }

            // Entity-specific sink. resolveFeedHandler() gates which entities
            // reach this point — extending the supported set is a one-line
            // change there + a new sink case here.
            let added = 0;
            let updated = 0;
            let indicators: Array<{ id: string; value: string; type: string }> | undefined;
            let sinkErrors: string[] = [];

            switch (manifest.entity) {
                case 'ioc': {
                    const sink = await iocSink(result.records as CanonicalIoc[]);
                    added = sink.added;
                    updated = sink.updated;
                    indicators = sink.indicators;
                    sinkErrors = sink.errors;
                    break;
                }
                case 'vulnerability': {
                    const sink = await vulnerabilitySink(result.records as CanonicalVulnerability[]);
                    added = sink.added;
                    updated = sink.updated;
                    sinkErrors = sink.errors;
                    break;
                }
                default:
                    // Defensive: resolveFeedHandler should have caught this; if it
                    // didn't, fail loud rather than silently dropping records.
                    throw new Error(`Engine handler has no sink for entity '${manifest.entity}'`);
            }
            errors.push(...sinkErrors);

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
                success: sinkErrors.length === 0 || added + updated > 0,
                pulsesProcessed: 1,
                indicatorsProcessed: result.stats.read,
                indicatorsAdded: added,
                indicatorsUpdated: updated,
                errors,
                indicators,
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
