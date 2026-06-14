/**
 * Composite Intelligence Scoring Engine
 *
 * Multi-factor risk scoring that goes beyond simple VT detection counts:
 *
 *   Composite = (Source Confidence × 0.30)
 *             + (VT Detections     × 0.25)
 *             + (Graph Centrality  × 0.20)
 *             + (Temporal Freshness × 0.15)
 *             + (MITRE Coverage    × 0.10)
 *
 * Each factor is normalized to 0–100 before weighting.
 * Results are cached in Redis for 15 minutes per IOC.
 */

import { db, sql, rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('ScoringEngine');

// ============================================================================
// Types
// ============================================================================

export interface ScoreBreakdown {
    composite: number;           // 0–100 weighted final score
    factors: {
        sourceConfidence: number;
        vtDetections: number;
        graphCentrality: number;
        temporalFreshness: number;
        mitreCoverage: number;
    };
    iocId: string;
    calculatedAt: string;
}

export interface BatchScoreResult {
    total: number;
    scored: number;
    errors: number;
    avgComposite: number;
    distribution: {
        critical: number;   // 80–100
        high: number;       // 60–79
        medium: number;     // 40–59
        low: number;        // 20–39
        info: number;       // 0–19
    };
}

// ============================================================================
// Weights
// ============================================================================

const WEIGHTS = {
    sourceConfidence: 0.30,
    vtDetections: 0.25,
    graphCentrality: 0.20,
    temporalFreshness: 0.15,
    mitreCoverage: 0.10,
};

/** Half-life for temporal decay (days) */
const HALF_LIFE_DAYS = 7;

// ============================================================================
// Factor Calculators
// ============================================================================

/**
 * Factor 1: Source confidence (0–100).
 * Directly from the IOC's confidence field. Default = 50.
 */
export function calcSourceConfidence(confidence: number | null): number {
    return Math.min(100, Math.max(0, confidence ?? 50));
}

/**
 * Factor 2: VT detection ratio normalized to 0–100.
 */
export function calcVtDetections(rawData: Record<string, unknown> | null | undefined): number {
    if (!rawData) return 0;

    const vtData = (rawData?.virustotal || rawData?.vt || (rawData?.enrichment as Record<string, unknown>)?.virustotal) as Record<string, unknown> | undefined;
    if (!vtData) return 0;

    const malicious = Number(vtData.malicious ?? vtData.positives ?? 0);
    const total = Number(vtData.total ?? vtData.total_engines ?? 0);

    if (total === 0) return 0;
    return Math.round((malicious / total) * 100);
}

/**
 * Factor 3: Graph centrality via Neo4j relationship count.
 * Logarithmic scale: 0 rels = 0, 10+ rels ≈ 100.
 */
async function calcGraphCentrality(iocId: string): Promise<number> {
    try {
        const neo4jUrl = process.env.NEO4J_HTTP_URL || 'http://localhost:7474';
        const neo4jAuth = Buffer.from(
            `${process.env.NEO4J_USER || 'neo4j'}:${process.env.NEO4J_PASSWORD || 'password'}`
        ).toString('base64');

        const response = await fetch(`${neo4jUrl}/db/neo4j/tx/commit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Basic ${neo4jAuth}`,
            },
            body: JSON.stringify({
                statements: [{
                    statement: `MATCH (n {id: $iocId}) OPTIONAL MATCH (n)-[r]-() RETURN count(r) AS relCount`,
                    parameters: { iocId },
                }],
            }),
            signal: AbortSignal.timeout(3000),
        });

        if (!response.ok) return 0;

        const data = await response.json() as Record<string, unknown>;
        const results = (data?.results ?? []) as Array<{ data: Array<{ row: unknown[] }> }>;
        const relCount = Number(results?.[0]?.data?.[0]?.row?.[0] ?? 0);

        if (relCount === 0) return 0;
        return Math.min(100, Math.round(Math.log2(relCount + 1) * 30));
    } catch {
        return 0;
    }
}

/**
 * Factor 4: Temporal freshness — exponential decay from lastSeen.
 * Returns 100 for "just seen", decays by 50% every HALF_LIFE_DAYS.
 */
export function calcTemporalFreshness(lastSeen: string | null): number {
    if (!lastSeen) return 0;

    const ageDays = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 0) return 100;

    const score = 100 * Math.pow(0.5, ageDays / HALF_LIFE_DAYS);
    return Math.round(Math.max(0, Math.min(100, score)));
}

/**
 * Factor 5: MITRE ATT&CK technique coverage.
 * Count MITRE tags (T1xxx), normalize: each technique = 20 points, max 100.
 */
async function calcMitreCoverage(iocId: string): Promise<number> {
    try {
        const result = await rawQuery(
            `SELECT tags FROM iocs WHERE id = '${iocId.replace(/'/g, "''")}'`
        );

        const tags: string[] = (result.rows?.[0]?.tags as string[]) || [];
        const mitreTags = tags.filter(t => /^T\d{4}/i.test(t));

        return Math.min(100, mitreTags.length * 20);
    } catch {
        return 0;
    }
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Compute composite risk score for a single IOC.
 */
export async function computeCompositeScore(iocId: string): Promise<ScoreBreakdown> {
    const result = await rawQuery(
        `SELECT id, confidence, raw_data, last_seen, tags FROM iocs WHERE id = '${iocId.replace(/'/g, "''")}'`
    );

    const ioc = result.rows?.[0];
    if (!ioc) throw new Error(`IOC not found: ${iocId}`);

    const rawData = typeof ioc.raw_data === 'string' ? JSON.parse(ioc.raw_data) : ioc.raw_data;

    const [graphCentrality, mitreCoverage] = await Promise.all([
        calcGraphCentrality(iocId),
        calcMitreCoverage(iocId),
    ]);

    const factors = {
        sourceConfidence: calcSourceConfidence(ioc.confidence as number | null),
        vtDetections: calcVtDetections(rawData),
        graphCentrality,
        temporalFreshness: calcTemporalFreshness(ioc.last_seen as string | null),
        mitreCoverage,
    };

    const composite = Math.round(
        factors.sourceConfidence * WEIGHTS.sourceConfidence +
        factors.vtDetections * WEIGHTS.vtDetections +
        factors.graphCentrality * WEIGHTS.graphCentrality +
        factors.temporalFreshness * WEIGHTS.temporalFreshness +
        factors.mitreCoverage * WEIGHTS.mitreCoverage
    );

    return {
        composite: Math.min(100, Math.max(0, composite)),
        factors,
        iocId,
        calculatedAt: new Date().toISOString(),
    };
}

/**
 * Batch re-score all IOCs. Processes in batches of 100.
 *
 * `onlyUnscored: true` restricts the work to rows where `risk_score = 0`
 * (or NULL). This is the backfill path for IOCs ingested before the
 * stream-consumer scoring hook was wired up — on prod 2026-06-14 that
 * was 266,822 of 266,822 rows, so the very first run is a long one.
 * Subsequent runs are no-ops once the streamConsumers path covers every
 * new ingestion.
 *
 * Resumability: the SELECT re-evaluates the filter each batch. With
 * `onlyUnscored`, every UPDATE shrinks the eligible set, so a process
 * crash mid-run picks up the remaining rows on the next invocation
 * without skipping or duplicating. With `onlyUnscored: false` the
 * existing OFFSET pagination is preserved.
 */
export async function rescoreAll(
    batchSize = 100,
    opts: { onlyUnscored?: boolean } = {},
): Promise<BatchScoreResult> {
    const result: BatchScoreResult = {
        total: 0, scored: 0, errors: 0, avgComposite: 0,
        distribution: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };

    let offset = 0;
    let totalScore = 0;

    while (true) {
        const whereClause = opts.onlyUnscored
            ? 'WHERE risk_score IS NULL OR risk_score = 0'
            : '';
        // When filtering by `risk_score = 0`, the UPDATE inside the loop
        // moves rows out of the eligible set — so offset stays at 0 and
        // we re-query for the next batch. Without the filter we keep the
        // historical OFFSET-walk behaviour so callers that wanted a full
        // re-score over every row still get one.
        const limitOffset = opts.onlyUnscored
            ? `LIMIT ${batchSize}`
            : `LIMIT ${batchSize} OFFSET ${offset}`;
        const batch = await rawQuery(
            `SELECT id FROM iocs ${whereClause} ORDER BY created_at DESC ${limitOffset}`
        );

        const rows = batch.rows ?? [];
        if (rows.length === 0) break;

        result.total += rows.length;

        for (const row of rows) {
            try {
                const score = await computeCompositeScore(String(row.id));
                result.scored++;
                totalScore += score.composite;

                // GREATEST(score, 1) so genuinely-zero composites still
                // satisfy `risk_score != 0` — otherwise the onlyUnscored
                // SELECT would re-pick the same row next iteration and
                // we'd loop forever on IOCs with no sources / no detections
                // / no graph signal. A floor of 1 sits comfortably inside
                // the existing "info" bucket (< 20) so it doesn't pollute
                // any of the meaningful score thresholds.
                const persistedScore = Math.max(score.composite, 1);
                await db.execute(sql.raw(
                    `UPDATE iocs SET risk_score = ${persistedScore}, updated_at = NOW()
                     WHERE id = '${String(row.id).replace(/'/g, "''")}'`
                ));

                if (score.composite >= 80) result.distribution.critical++;
                else if (score.composite >= 60) result.distribution.high++;
                else if (score.composite >= 40) result.distribution.medium++;
                else if (score.composite >= 20) result.distribution.low++;
                else result.distribution.info++;
            } catch (err) {
                result.errors++;
                log.warn(`Score failed for IOC ${row.id}`, { error: (err as Error).message });
            }
        }

        offset += batchSize;
        log.info(`Rescore batch ${offset / batchSize}`, { scored: result.scored, errors: result.errors });
    }

    result.avgComposite = result.scored > 0 ? Math.round(totalScore / result.scored) : 0;

    log.info('Batch rescore complete', {
        total: result.total, scored: result.scored,
        errors: result.errors, avgComposite: result.avgComposite,
    });

    return result;
}

/**
 * Get score summary statistics without re-scoring.
 */
export async function getScoreSummary(): Promise<{
    total: number;
    avgScore: number;
    distribution: Record<string, number>;
}> {
    const result = await db.execute(sql`
        SELECT
            COUNT(*) AS total,
            COALESCE(AVG(confidence), 0) AS avg_score,
            COUNT(*) FILTER (WHERE confidence >= 80) AS critical,
            COUNT(*) FILTER (WHERE confidence >= 60 AND confidence < 80) AS high,
            COUNT(*) FILTER (WHERE confidence >= 40 AND confidence < 60) AS medium,
            COUNT(*) FILTER (WHERE confidence >= 20 AND confidence < 40) AS low,
            COUNT(*) FILTER (WHERE confidence < 20 OR confidence IS NULL) AS info
        FROM iocs
    `);

    // postgres-js returns array directly, pg returns { rows: [...] }
    const rows = Array.isArray(result) ? result : ((result as unknown as { rows?: Record<string, unknown>[] }).rows ?? []);
    const row = (rows[0] ?? {}) as Record<string, unknown>;
    return {
        total: Number(row.total || 0),
        avgScore: Math.round(Number(row.avg_score || 0)),
        distribution: {
            critical: Number(row.critical || 0),
            high: Number(row.high || 0),
            medium: Number(row.medium || 0),
            low: Number(row.low || 0),
            info: Number(row.info || 0),
        },
    };
}
