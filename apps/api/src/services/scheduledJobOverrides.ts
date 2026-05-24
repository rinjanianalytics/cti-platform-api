/**
 * Read / write access to the `scheduled_job_overrides` table.
 *
 * The override table is sparse — most jobs run on the code-default
 * cadence. A row exists only when an admin has toggled the job off or
 * picked an interval preset. Consumers should always fall back to the
 * code-defined schedule when a row is missing.
 */

import { db, eq } from '@rinjani/db';
import { scheduledJobOverrides } from '@rinjani/db/schema';
import type { ScheduledJobOverride } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';
import { AppError } from '../lib/errors';

const log = createLogger('ScheduledJobOverrides');

/** Curated interval presets — admin picks one, we map to a cron pattern. */
export const INTERVAL_PRESETS = {
    '15m':    '*/15 * * * *',
    '30m':    '*/30 * * * *',
    '1h':     '0 * * * *',
    '4h':     '0 */4 * * *',
    '6h':     '0 */6 * * *',
    'daily':  '0 2 * * *',     // 02:00 local
    'weekly': '0 4 * * 0',     // Sunday 04:00 local
} as const;

export type IntervalPreset = keyof typeof INTERVAL_PRESETS;

export function isIntervalPreset(value: unknown): value is IntervalPreset {
    return typeof value === 'string' && value in INTERVAL_PRESETS;
}

/** Map a preset → cron, or return null if no preset (caller uses default). */
export function presetToCron(preset: string | null | undefined): string | null {
    if (!preset || !isIntervalPreset(preset)) return null;
    return INTERVAL_PRESETS[preset];
}

/**
 * Migration 0032 creates `scheduled_job_overrides`. When it hasn't been
 * applied yet, reads degrade gracefully to "no overrides → use code
 * defaults" (the system is designed so this is correct behaviour). Writes
 * surface a clear, actionable error — silently swallowing them would
 * lie to the admin clicking Save.
 *
 * 42P01 is Postgres's "undefined_table". We rate-limit the warning log
 * so a polling dashboard doesn't spam, but we don't latch the state —
 * if the migration runs mid-session the next call succeeds naturally.
 */
function isMissingTableError(err: unknown): boolean {
    return (err as { code?: string })?.code === '42P01';
}

/**
 * Migration-missing error surfaced to the client. Extends AppError so it
 * flows through the existing error envelope (slice 4): `success: false`,
 * `error: { code: 'OVERRIDES_TABLE_MISSING', message, statusCode: 503 }`.
 * The dashboard catches by `err.code` and shows the actionable message.
 */
export class OverridesUnavailableError extends AppError {
    constructor() {
        super(
            'scheduled_job_overrides table is missing. Run: pnpm --filter @rinjani/db db:apply --baseline-until=30 — then save again.',
            { statusCode: 503, code: 'OVERRIDES_TABLE_MISSING' },
        );
    }
}

let lastWarnAt = 0;
const WARN_THROTTLE_MS = 60_000;

function warnTableMissing() {
    const now = Date.now();
    if (now - lastWarnAt < WARN_THROTTLE_MS) return;
    lastWarnAt = now;
    log.warn('scheduled_job_overrides table missing — run migration 0032. Reads degrade to code defaults; writes will refuse.');
}

export async function listOverrides(): Promise<ScheduledJobOverride[]> {
    try {
        return await db.select().from(scheduledJobOverrides);
    } catch (err) {
        if (isMissingTableError(err)) {
            warnTableMissing();
            return [];
        }
        throw err;
    }
}

export async function getOverride(jobKey: string): Promise<ScheduledJobOverride | null> {
    try {
        const [row] = await db
            .select()
            .from(scheduledJobOverrides)
            .where(eq(scheduledJobOverrides.jobKey, jobKey))
            .limit(1);
        return row ?? null;
    } catch (err) {
        if (isMissingTableError(err)) {
            warnTableMissing();
            return null;
        }
        throw err;
    }
}

/**
 * Upsert an override for a job. `null` on a field clears it; absence on a
 * field keeps the prior value.
 */
export async function upsertOverride(
    jobKey: string,
    patch: {
        enabled?: boolean;
        intervalPreset?: string | null;
        payload?: Record<string, unknown> | null;
    },
    userId: string | null,
): Promise<ScheduledJobOverride> {
    if (patch.intervalPreset !== undefined && patch.intervalPreset !== null && !isIntervalPreset(patch.intervalPreset)) {
        throw new Error(`Invalid intervalPreset: ${patch.intervalPreset}`);
    }

    const existing = await getOverride(jobKey);
    const row: ScheduledJobOverride = existing
        ? {
            ...existing,
            ...(patch.enabled !== undefined && { enabled: patch.enabled }),
            ...(patch.intervalPreset !== undefined && { intervalPreset: patch.intervalPreset }),
            ...(patch.payload !== undefined && { payload: patch.payload }),
            updatedAt: new Date(),
            updatedBy: userId,
        }
        : {
            jobKey,
            enabled: patch.enabled ?? true,
            intervalPreset: patch.intervalPreset ?? null,
            payload: patch.payload ?? null,
            updatedAt: new Date(),
            updatedBy: userId,
        };

    try {
        if (existing) {
            await db
                .update(scheduledJobOverrides)
                .set({
                    enabled: row.enabled,
                    intervalPreset: row.intervalPreset,
                    payload: row.payload,
                    updatedAt: row.updatedAt,
                    updatedBy: row.updatedBy,
                })
                .where(eq(scheduledJobOverrides.jobKey, jobKey));
        } else {
            await db.insert(scheduledJobOverrides).values(row);
        }
    } catch (err) {
        if (isMissingTableError(err)) {
            warnTableMissing();
            throw new OverridesUnavailableError();
        }
        throw err;
    }

    log.info('Scheduled job override saved', {
        jobKey,
        enabled: row.enabled,
        intervalPreset: row.intervalPreset,
        userId,
    });
    return row;
}
