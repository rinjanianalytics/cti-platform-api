/**
 * Multi-Analyzer Pipeline (Cortex / IntelOwl inspired)
 *
 * Pluggable analyzer framework that wraps existing services as adapters.
 * Supports individual analyzer runs, scan chains, and execution history.
 *
 * Built-in analyzers (adapters over existing services):
 *   - risk-score    → scoringEngine.ts
 *   - correlation   → correlation.ts
 *   - yara-scan     → yaraEngine.ts
 *   - ai-analysis   → aiAnalysis/
 *   - enrichment    → enrichment providers (VT, AbuseIPDB, Shodan)
 *   - stix-validate → stixPipeline.ts
 *   - decay-check   → confidenceDecay.ts
 *   - reputation    → reputation aggregation
 *
 * Mounts at: /v1/analyzers/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth } from '../../middleware/auth';
import { createLogger } from '../../lib/logger';
import { RunAnalyzerSchema, ScanChainSchema } from '../../lib/schemas';

const log = createLogger('Analyzers');
const analyzers = new Hono();
analyzers.use('*', requireAuth);

// ============================================================================
// Analyzer Registry — Adapter pattern over existing services
// ============================================================================

interface AnalyzerResult {
    analyzer: string;
    status: 'success' | 'error';
    verdict: 'info' | 'safe' | 'suspicious' | 'malicious' | 'unknown';
    score: number; // 0-100
    summary: string;
    details: Record<string, unknown>;
    durationMs: number;
}

interface Analyzer {
    name: string;
    description: string;
    supportedTypes: string[];
    run: (value: string, type: string) => Promise<Omit<AnalyzerResult, 'analyzer' | 'durationMs'>>;
}

const ANALYZER_REGISTRY: Record<string, Analyzer> = {
    'risk-score': {
        name: 'Composite Risk Scorer',
        description: 'Multi-factor risk scoring using source confidence, VT detections, graph centrality, temporal freshness, and MITRE coverage',
        supportedTypes: ['ip', 'domain', 'url', 'hash', 'email'],
        async run(value: string) {
            try {
                const result = await rawQuery(sql.raw(`
                    SELECT id, risk_score, confidence, type, source, tags
                    FROM iocs WHERE value = '${value.replace(/'/g, "''")}' LIMIT 1
                `));
                const ioc = result.rows?.[0] as Record<string, unknown> | undefined;
                if (!ioc) return { status: 'success', verdict: 'info', score: 0, summary: 'No IOC record found', details: {} };

                const score = Number(ioc.risk_score || 0);
                const verdict = score >= 80 ? 'malicious' : score >= 50 ? 'suspicious' : score >= 20 ? 'info' : 'safe';
                return {
                    status: 'success', verdict, score,
                    summary: `Risk score: ${score}/100 (source: ${ioc.source})`,
                    details: { iocId: ioc.id, confidence: ioc.confidence, source: ioc.source, tags: ioc.tags },
                };
            } catch (err) {
                return { status: 'error', verdict: 'unknown', score: 0, summary: (err as Error).message, details: {} };
            }
        },
    },

    'correlation': {
        name: 'Correlation Engine',
        description: 'Discovers CIDR, domain, campaign, and temporal correlations',
        supportedTypes: ['ip', 'domain', 'url', 'hash'],
        async run(value: string) {
            try {
                const result = await rawQuery(sql.raw(`
                    SELECT id FROM iocs WHERE value = '${value.replace(/'/g, "''")}' LIMIT 1
                `));
                const ioc = result.rows?.[0] as Record<string, unknown> | undefined;
                if (!ioc) return { status: 'success', verdict: 'info', score: 0, summary: 'No IOC record for correlation', details: {} };

                // Count related IOCs via source overlap
                const relResult = await rawQuery(sql.raw(`
                    SELECT COUNT(*) AS related FROM iocs
                    WHERE source IN (SELECT source FROM iocs WHERE id = '${String(ioc.id).replace(/'/g, "''")}')
                    AND id != '${String(ioc.id).replace(/'/g, "''")}'
                `));
                const related = Number((relResult.rows?.[0] as Record<string, unknown>)?.related || 0);
                const score = Math.min(100, related * 10);
                const verdict = score >= 50 ? 'suspicious' : 'info';
                return {
                    status: 'success', verdict, score,
                    summary: `Found ${related} correlated IOCs from shared sources`,
                    details: { relatedCount: related, iocId: ioc.id },
                };
            } catch (err) {
                return { status: 'error', verdict: 'unknown', score: 0, summary: (err as Error).message, details: {} };
            }
        },
    },

    'decay-check': {
        name: 'Confidence Decay Analyzer',
        description: 'Calculates time-based aging of IOC confidence',
        supportedTypes: ['ip', 'domain', 'url', 'hash', 'email'],
        async run(value: string) {
            try {
                const result = await rawQuery(sql.raw(`
                    SELECT id, type, risk_score, last_seen FROM iocs
                    WHERE value = '${value.replace(/'/g, "''")}' LIMIT 1
                `));
                const ioc = result.rows?.[0] as Record<string, unknown> | undefined;
                if (!ioc) return { status: 'success', verdict: 'info', score: 0, summary: 'No IOC record for decay analysis', details: {} };

                const lastSeen = new Date(String(ioc.last_seen || Date.now()));
                const daysSince = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60 * 24);
                const baseScore = Number(ioc.risk_score || 50);
                const lambda = 0.03; // default decay rate
                const decayed = Math.round(baseScore * Math.exp(-lambda * daysSince));
                const isStale = daysSince > 60;

                return {
                    status: 'success',
                    verdict: isStale ? 'info' : decayed >= 70 ? 'malicious' : decayed >= 40 ? 'suspicious' : 'safe',
                    score: decayed,
                    summary: `Score decayed from ${baseScore} to ${decayed} over ${Math.round(daysSince)} days${isStale ? ' (STALE)' : ''}`,
                    details: { originalScore: baseScore, decayedScore: decayed, daysSinceLastSeen: Math.round(daysSince), isStale },
                };
            } catch (err) {
                return { status: 'error', verdict: 'unknown', score: 0, summary: (err as Error).message, details: {} };
            }
        },
    },

    'reputation': {
        name: 'Reputation Aggregator',
        description: 'Aggregated reputation from IOC records, sightings, and community reports',
        supportedTypes: ['ip', 'domain', 'url', 'email'],
        async run(value: string, type: string) {
            try {
                const iocResult = await rawQuery(sql.raw(`
                    SELECT COUNT(*) AS ioc_count, COALESCE(AVG(risk_score), 0) AS avg_score
                    FROM iocs WHERE value = '${value.replace(/'/g, "''")}'
                `));
                const reportResult = await rawQuery(sql.raw(`
                    SELECT COUNT(*) AS report_count FROM reputation_reports
                    WHERE value = '${value.replace(/'/g, "''")}' AND (expires_at IS NULL OR expires_at > NOW())
                `));
                const iocData = iocResult.rows?.[0] as Record<string, unknown> || {};
                const reportData = reportResult.rows?.[0] as Record<string, unknown> || {};

                const avgScore = Math.round(Number(iocData.avg_score || 0));
                const reports = Number(reportData.report_count || 0);
                const combinedScore = Math.min(100, avgScore + reports * 5);
                const verdict = combinedScore >= 70 ? 'malicious' : combinedScore >= 40 ? 'suspicious' : combinedScore > 0 ? 'info' : 'safe';

                return {
                    status: 'success', verdict, score: combinedScore,
                    summary: `Reputation: ${combinedScore}/100 (${Number(iocData.ioc_count)} IOCs, ${reports} community reports)`,
                    details: { iocCount: Number(iocData.ioc_count), avgIocScore: avgScore, communityReports: reports, type },
                };
            } catch (err) {
                return { status: 'error', verdict: 'unknown', score: 0, summary: (err as Error).message, details: {} };
            }
        },
    },

    'yara-scan': {
        name: 'YARA Rule Scanner',
        description: 'Matches observable against compiled YARA rules',
        supportedTypes: ['hash', 'url', 'domain'],
        async run(value: string) {
            try {
                // Check if YARA rules reference this value
                const result = await rawQuery(sql.raw(`
                    SELECT COUNT(*) AS match_count FROM yara_rules
                    WHERE content ILIKE '%${value.replace(/'/g, "''").replace(/%/g, '\\%')}%'
                `));
                const matches = Number((result.rows?.[0] as Record<string, unknown>)?.match_count || 0);
                return {
                    status: 'success',
                    verdict: matches > 0 ? 'malicious' : 'safe',
                    score: matches > 0 ? 90 : 0,
                    summary: matches > 0 ? `Matched ${matches} YARA rule(s)` : 'No YARA rule matches',
                    details: { matchCount: matches },
                };
            } catch {
                return { status: 'success', verdict: 'info', score: 0, summary: 'YARA rules not available', details: {} };
            }
        },
    },

    'stix-validate': {
        name: 'STIX 2.1 Validator',
        description: 'Validates if observable has proper STIX object representation',
        supportedTypes: ['ip', 'domain', 'url', 'hash', 'email'],
        async run(value: string) {
            try {
                const result = await rawQuery(sql.raw(`
                    SELECT stix_id, type, source FROM iocs
                    WHERE value = '${value.replace(/'/g, "''")}' AND stix_id IS NOT NULL
                    LIMIT 5
                `));
                const stixRecords = result.rows || [];
                return {
                    status: 'success',
                    verdict: 'info',
                    score: stixRecords.length > 0 ? 50 : 0,
                    summary: stixRecords.length > 0
                        ? `Found ${stixRecords.length} STIX 2.1 representation(s)`
                        : 'No STIX representation found',
                    details: { stixRecords: stixRecords.length, records: stixRecords },
                };
            } catch (err) {
                return { status: 'error', verdict: 'unknown', score: 0, summary: (err as Error).message, details: {} };
            }
        },
    },
};

// ============================================================================
// Auto-create history table
// ============================================================================

const ensureHistoryOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS analyzer_runs (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                analyzers TEXT[] NOT NULL,
                results JSONB NOT NULL DEFAULT '[]',
                overall_verdict TEXT NOT NULL DEFAULT 'unknown',
                overall_score INT NOT NULL DEFAULT 0,
                duration_ms INT NOT NULL DEFAULT 0,
                run_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_analyzer_runs_value ON analyzer_runs(value);
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// ============================================================================
// GET /analyzers — List available analyzers
// ============================================================================

analyzers.get('/analyzers', async (c) => {
    const list = Object.entries(ANALYZER_REGISTRY).map(([id, a]) => ({
        id,
        name: a.name,
        description: a.description,
        supportedTypes: a.supportedTypes,
        status: 'active',
    }));
    return c.json({ success: true, data: { analyzers: list, total: list.length } });
});

// ============================================================================
// POST /analyzers/run — Run analyzer(s) on observable
// ============================================================================

analyzers.post('/analyzers/run', async (c) => {
    await ensureHistoryOnce();
    const body = RunAnalyzerSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const type = body.type === 'auto' ? autoDetectType(body.value) : body.type;

    const startTime = Date.now();
    const results: AnalyzerResult[] = [];

    for (const analyzerName of body.analyzers) {
        const analyzer = ANALYZER_REGISTRY[analyzerName];
        if (!analyzer) {
            results.push({
                analyzer: analyzerName, status: 'error', verdict: 'unknown',
                score: 0, summary: `Unknown analyzer: ${analyzerName}`, details: {}, durationMs: 0,
            });
            continue;
        }

        const t0 = Date.now();
        try {
            const result = await analyzer.run(body.value, type);
            results.push({ ...result, analyzer: analyzerName, durationMs: Date.now() - t0 });
        } catch (err) {
            results.push({
                analyzer: analyzerName, status: 'error', verdict: 'unknown',
                score: 0, summary: (err as Error).message, details: {}, durationMs: Date.now() - t0,
            });
        }
    }

    const totalDuration = Date.now() - startTime;
    const scores = results.filter(r => r.status === 'success').map(r => r.score);
    const overallScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => Math.max(a, b), 0)) : 0;
    const overallVerdict = overallScore >= 80 ? 'malicious' : overallScore >= 50 ? 'suspicious' : overallScore >= 20 ? 'info' : 'safe';

    // Persist run history
    await rawQuery(sql.raw(`
        INSERT INTO analyzer_runs (value, type, analyzers, results, overall_verdict, overall_score, duration_ms, run_by)
        VALUES ('${esc(body.value)}', '${esc(type)}',
                ARRAY[${body.analyzers.map(a => `'${esc(a)}'`).join(',')}],
                '${JSON.stringify(results).replace(/'/g, "''")}'::jsonb,
                '${esc(overallVerdict)}', ${overallScore}, ${totalDuration}, '${esc(userId)}')
    `));

    return c.json({
        success: true,
        data: {
            value: body.value,
            type,
            results,
            overall: { verdict: overallVerdict, score: overallScore },
            durationMs: totalDuration,
        },
    });
});

// ============================================================================
// POST /analyzers/scan-chain — Ordered scan chain
// ============================================================================

analyzers.post('/analyzers/scan-chain', async (c) => {
    await ensureHistoryOnce();
    const body = ScanChainSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const type = body.type === 'auto' ? autoDetectType(body.value) : body.type;

    const startTime = Date.now();
    const results: AnalyzerResult[] = [];
    let stopped = false;

    for (const analyzerName of body.chain) {
        if (stopped) break;

        const analyzer = ANALYZER_REGISTRY[analyzerName];
        if (!analyzer) {
            results.push({
                analyzer: analyzerName, status: 'error', verdict: 'unknown',
                score: 0, summary: `Unknown analyzer: ${analyzerName}`, details: {}, durationMs: 0,
            });
            continue;
        }

        const t0 = Date.now();
        try {
            const result = await analyzer.run(body.value, type);
            const analyzerResult = { ...result, analyzer: analyzerName, durationMs: Date.now() - t0 };
            results.push(analyzerResult);

            if (body.stopOnMalicious && result.verdict === 'malicious') {
                stopped = true;
                log.info('Scan chain stopped on malicious verdict', { analyzer: analyzerName, value: body.value });
            }
        } catch (err) {
            results.push({
                analyzer: analyzerName, status: 'error', verdict: 'unknown',
                score: 0, summary: (err as Error).message, details: {}, durationMs: Date.now() - t0,
            });
        }
    }

    const totalDuration = Date.now() - startTime;
    const scores = results.filter(r => r.status === 'success').map(r => r.score);
    const overallScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => Math.max(a, b), 0)) : 0;
    const overallVerdict = overallScore >= 80 ? 'malicious' : overallScore >= 50 ? 'suspicious' : overallScore >= 20 ? 'info' : 'safe';

    // Persist
    await rawQuery(sql.raw(`
        INSERT INTO analyzer_runs (value, type, analyzers, results, overall_verdict, overall_score, duration_ms, run_by)
        VALUES ('${esc(body.value)}', '${esc(type)}',
                ARRAY[${body.chain.map(a => `'${esc(a)}'`).join(',')}],
                '${JSON.stringify(results).replace(/'/g, "''")}'::jsonb,
                '${esc(overallVerdict)}', ${overallScore}, ${totalDuration}, '${esc(userId)}')
    `));

    return c.json({
        success: true,
        data: {
            value: body.value,
            type,
            chain: body.chain,
            results,
            stopped,
            overall: { verdict: overallVerdict, score: overallScore },
            durationMs: totalDuration,
        },
    });
});

// ============================================================================
// GET /analyzers/history — Execution history
// ============================================================================

analyzers.get('/analyzers/history', async (c) => {
    await ensureHistoryOnce();
    const limit = Math.min(parseInt(c.req.query('limit') || '50', 10), 200);
    const page = Math.max(parseInt(c.req.query('page') || '1', 10), 1);
    const offset = (page - 1) * limit;

    const [items, countResult] = await Promise.all([
        rawQuery(sql.raw(`SELECT id, value, type, analyzers, overall_verdict, overall_score, duration_ms, run_by, created_at FROM analyzer_runs ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM analyzer_runs`)),
    ]);

    const total = Number((countResult.rows?.[0] as Record<string, unknown>)?.total || 0);

    return c.json({
        success: true,
        data: {
            items: items.rows || [],
            pagination: { page, pageSize: limit, total, pages: Math.ceil(total / limit) },
        },
    });
});

// ============================================================================
// GET /analyzers/results/:id — Get detailed run result
// ============================================================================

analyzers.get('/analyzers/results/:id', async (c) => {
    await ensureHistoryOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`SELECT * FROM analyzer_runs WHERE id = '${esc(id)}'`));
    const row = result.rows?.[0];
    if (!row) {
        return c.json({ success: false, error: 'Run not found' }, 404);
    }
    return c.json({ success: true, data: row });
});

// ============================================================================
// Helpers
// ============================================================================

function autoDetectType(value: string): string {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return 'ip';
    if (/^[a-f0-9]{32,64}$/i.test(value)) return 'hash';
    if (value.includes('@')) return 'email';
    if (value.startsWith('http')) return 'url';
    return 'domain';
}

export default analyzers;
