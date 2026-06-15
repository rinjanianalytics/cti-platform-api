/**
 * Structured Logger
 *
 * JSON-formatted logging with service prefixes, severity levels,
 * correlation IDs, and error serialization.
 */

import { randomUUID } from 'crypto';

// ============================================================================
// Types
// ============================================================================

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';

interface LogEntry {
    timestamp: string;
    level: LogLevel;
    service: string;
    message: string;
    correlationId?: string;
    data?: Record<string, unknown>;
    error?: {
        name: string;
        message: string;
        stack?: string;
        code?: string;
    };
}

// ============================================================================
// Logger Factory
// ============================================================================

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
};

const MIN_LEVEL = (process.env.LOG_LEVEL as LogLevel) || 'info';

function shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[MIN_LEVEL];
}

/**
 * Format postgres-js errors (and any object with a postgres-style shape) into
 * a single diagnostic string. postgres-js errors aren't Error instances —
 * they're plain objects with `.code` (e.g. '42P07'), `.detail`, `.hint`,
 * `.position`, `.where`, `.message_primary`. `String(err)` on these returns
 * `'[object Object]'`, hiding the real failure reason.
 *
 * Format: `<code> <message> | detail=<…> | hint=<…>` — short enough to grep,
 * structured enough to act on. Returns null when nothing useful was found
 * (caller can then fall through to a generic stringification).
 */
function formatPgErrorMessage(err: unknown): string | null {
    if (err == null || typeof err !== 'object') return null;
    const e = err as {
        code?: unknown; message?: unknown; detail?: unknown; hint?: unknown;
        where?: unknown; routine?: unknown; message_primary?: unknown;
    };
    const parts: string[] = [];
    if (typeof e.code === 'string') parts.push(e.code);
    const msg = e.message_primary ?? e.message;
    if (typeof msg === 'string') parts.push(msg);
    if (typeof e.detail === 'string') parts.push(`detail=${e.detail}`);
    if (typeof e.hint === 'string') parts.push(`hint=${e.hint}`);
    if (typeof e.where === 'string') parts.push(`where=${e.where}`);
    return parts.length > 0 ? parts.join(' | ') : null;
}

function serializeError(err: unknown): LogEntry['error'] | undefined {
    if (!err) return undefined;
    if (err instanceof Error) {
        return {
            name: err.name,
            message: err.message,
            stack: process.env.NODE_ENV === 'production' ? undefined : err.stack,
            code: (err as Error & { code?: string }).code,
        };
    }
    // Non-Error postgres-js error → format with code + message + detail + hint.
    const pgMsg = formatPgErrorMessage(err);
    if (pgMsg !== null) {
        const e = err as { code?: unknown };
        return {
            name: 'PgError',
            message: pgMsg,
            code: typeof e.code === 'string' ? e.code : undefined,
        };
    }
    // Last-ditch fallback. Try JSON; fall back to String() if cyclic.
    let serialized: string;
    try {
        serialized = JSON.stringify(err);
    } catch {
        serialized = String(err);
    }
    return { name: 'UnknownError', message: serialized };
}

function emit(entry: LogEntry): void {
    const output = JSON.stringify(entry);
    switch (entry.level) {
        case 'error':
        case 'fatal':
            console.error(output);
            break;
        case 'warn':
            console.warn(output);
            break;
        case 'debug':
            console.debug(output);
            break;
        default:
            console.log(output);
    }
}

// ============================================================================
// Public API
// ============================================================================

export interface Logger {
    debug(message: string, data?: Record<string, unknown>): void;
    info(message: string, data?: Record<string, unknown>): void;
    warn(message: string, data?: Record<string, unknown>): void;
    error(message: string, err?: unknown, data?: Record<string, unknown>): void;
    fatal(message: string, err?: unknown, data?: Record<string, unknown>): void;
    child(service: string): Logger;
}

/**
 * Create a logger scoped to a service.
 *
 * @example
 * const log = createLogger('WebSearchWorker');
 * log.info('Processing job', { jobId: '123' });
 * log.error('Fan-out write failed', err, { target: 'neo4j' });
 */
export function createLogger(service: string, correlationId?: string): Logger {
    const cid = correlationId ?? randomUUID();

    function log(level: LogLevel, message: string, err?: unknown, data?: Record<string, unknown>) {
        if (!shouldLog(level)) return;
        emit({
            timestamp: new Date().toISOString(),
            level,
            service,
            message,
            correlationId: cid,
            data,
            error: serializeError(err),
        });
    }

    /**
     * Tolerate the common misuse pattern `log.error(msg, { error: '<msg>' })`
     * — historically ~10 call sites in this repo passed a data-dict in the
     * err slot, which caused serializeError to emit `'[object Object]'`. If
     * the err arg is a plain non-Error object AND no data arg was provided,
     * treat it as the data dict and lift any string `error` field to a
     * synthetic Error so the diagnostic actually shows up.
     */
    function errorOrFatal(level: 'error' | 'fatal', msg: string, errOrData?: unknown, data?: Record<string, unknown>) {
        const isDataDictMisuse =
            errOrData != null &&
            typeof errOrData === 'object' &&
            !(errOrData instanceof Error) &&
            formatPgErrorMessage(errOrData) === null && // not a postgres-js error
            data === undefined;
        if (isDataDictMisuse) {
            const dict = errOrData as Record<string, unknown>;
            const errMsg = typeof dict.error === 'string' ? dict.error : undefined;
            const synthetic = errMsg ? new Error(errMsg) : undefined;
            if (synthetic) synthetic.name = 'LegacyDataDictError';
            log(level, msg, synthetic, dict);
            return;
        }
        log(level, msg, errOrData, data);
    }

    return {
        debug: (msg, data) => log('debug', msg, undefined, data),
        info: (msg, data) => log('info', msg, undefined, data),
        warn: (msg, data) => log('warn', msg, undefined, data),
        error: (msg, err, data) => errorOrFatal('error', msg, err, data),
        fatal: (msg, err, data) => errorOrFatal('fatal', msg, err, data),
        child: (childService) => createLogger(`${service}:${childService}`, cid),
    };
}
