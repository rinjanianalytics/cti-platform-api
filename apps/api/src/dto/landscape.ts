/**
 * Landscape DTOs.
 *
 * The `/v1/landscape/overview` endpoint returns aggregated counts from
 * several `SELECT COUNT(*) ...` queries. Postgres returns bigint as
 * string, so every count field would arrive at the client as `"1234"`
 * unless coerced here. Same for `AVG(...)` columns.
 *
 * This module owns the entire response shape for the overview endpoint —
 * the route handler runs the queries, hands the raw rows in, and gets
 * back a typed DTO ready for `c.json()`.
 */

import { toCount } from './common';

export interface LandscapeIocsStat {
    total: number;
    critical: number;
    high: number;
    avgScore: number;
}

export interface LandscapeVulnStat {
    total: number;
    critical: number;
    high: number;
}

export interface LandscapeNotifStat {
    total: number;
}

export interface LandscapeDistribution<K extends string> {
    [key: string]: unknown;
}

export interface LandscapeOverviewDTO {
    period: string;
    iocs: LandscapeIocsStat;
    vulnerabilities: LandscapeVulnStat;
    notifications: LandscapeNotifStat;
    iocTypeDistribution: Array<{ type: string; count: number }>;
    topSources: Array<{ source: string; count: number }>;
    severityDistribution: Array<{ severity: string | null; count: number }>;
}

type IocStatRow = Record<string, unknown>;
type SimpleRow = Record<string, unknown>;

export function toLandscapeOverview(input: {
    period: string;
    iocStats: IocStatRow | undefined;
    vulnStats: SimpleRow | undefined;
    notifCount: SimpleRow | undefined;
    iocTypes: SimpleRow[] | undefined;
    topSources: SimpleRow[] | undefined;
    severityDist: SimpleRow[] | undefined;
}): LandscapeOverviewDTO {
    const ios = input.iocStats ?? {};
    const vulns = input.vulnStats ?? {};
    const notifs = input.notifCount ?? {};

    return {
        period: input.period,
        iocs: {
            total:    toCount(ios.total),
            critical: toCount(ios.critical),
            high:     toCount(ios.high),
            // Round to a whole-number "score" — matches the prior route's behaviour
            // where `Math.round` was applied to the avg.
            avgScore: Math.round(toCount(ios.avg_score)),
        },
        vulnerabilities: {
            total:    toCount(vulns.total),
            critical: toCount(vulns.critical),
            high:     toCount(vulns.high),
        },
        notifications: {
            total: toCount(notifs.total),
        },
        iocTypeDistribution: (input.iocTypes ?? []).map(r => ({
            type: String(r.type ?? ''),
            count: toCount(r.count),
        })),
        topSources: (input.topSources ?? []).map(r => ({
            source: String(r.source ?? ''),
            count: toCount(r.count),
        })),
        severityDistribution: (input.severityDist ?? []).map(r => ({
            severity: (r.severity as string | null) ?? null,
            count: toCount(r.count),
        })),
    };
}
