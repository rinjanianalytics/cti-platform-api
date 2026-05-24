/**
 * Standardized Error Handling
 *
 * Hierarchical AppError classes for consistent error propagation
 * across API routes, workers, and database operations.
 */

// ============================================================================
// Base Error
// ============================================================================

export class AppError extends Error {
    /** HTTP status code (for API responses) */
    readonly statusCode: number;
    /** Machine-readable error code */
    readonly code: string;
    /** True = expected operational error; False = programmer bug */
    readonly isOperational: boolean;
    /** Arbitrary context for logging */
    readonly context?: Record<string, unknown>;

    constructor(
        message: string,
        opts: {
            statusCode?: number;
            code?: string;
            isOperational?: boolean;
            context?: Record<string, unknown>;
            cause?: Error;
        } = {},
    ) {
        super(message, { cause: opts.cause });
        this.name = this.constructor.name;
        this.statusCode = opts.statusCode ?? 500;
        this.code = opts.code ?? 'INTERNAL_ERROR';
        this.isOperational = opts.isOperational ?? true;
        this.context = opts.context;

        // Capture stack trace, excluding constructor call
        Error.captureStackTrace?.(this, this.constructor);
    }

    /**
     * Serialize for JSON logging / API responses.
     *
     * Returns the canonical inner-error shape used by `middleware/error.ts`
     * — `{code, message, details?}`. Previously emitted `{error: code, ...}`
     * which forced the client to branch on `typeof error === 'string'` vs.
     * object. All error paths (AppError, ZodError, HTTPException,
     * unhandled) now produce the same inner shape.
     */
    toJSON() {
        return {
            code: this.code,
            message: this.message,
            statusCode: this.statusCode,
            ...(this.context ? { details: this.context } : {}),
        };
    }
}

// ============================================================================
// Specific Error Types
// ============================================================================

/** 400 — Bad request / validation failure */
export class ValidationError extends AppError {
    constructor(message: string, context?: Record<string, unknown>) {
        super(message, { statusCode: 400, code: 'VALIDATION_ERROR', context });
    }
}

/** 404 — Resource not found */
export class NotFoundError extends AppError {
    constructor(resource: string, id?: string) {
        super(`${resource}${id ? ` '${id}'` : ''} not found`, {
            statusCode: 404,
            code: 'NOT_FOUND',
            context: { resource, id },
        });
    }
}

/** 503 — Database or external service unavailable */
export class DatabaseError extends AppError {
    constructor(service: string, cause?: Error) {
        super(`Database error: ${service}`, {
            statusCode: 503,
            code: 'DATABASE_ERROR',
            context: { service },
            cause,
        });
    }
}

/** 502 — External service (SearXNG, VirusTotal, etc.) failure */
export class ExternalServiceError extends AppError {
    constructor(service: string, cause?: Error) {
        super(`External service failed: ${service}`, {
            statusCode: 502,
            code: 'EXTERNAL_SERVICE_ERROR',
            context: { service },
            cause,
        });
    }
}

/** 500 — Queue or worker failure */
export class QueueError extends AppError {
    constructor(queue: string, message: string, cause?: Error) {
        super(message, {
            statusCode: 500,
            code: 'QUEUE_ERROR',
            context: { queue },
            cause,
        });
    }
}

/** 403 — Forbidden / insufficient permissions */
export class ForbiddenError extends AppError {
    constructor(message = 'Forbidden') {
        super(message, { statusCode: 403, code: 'FORBIDDEN' });
    }
}

/** 409 — Resource conflict */
export class ConflictError extends AppError {
    constructor(message: string, context?: Record<string, unknown>) {
        super(message, { statusCode: 409, code: 'CONFLICT', context });
    }
}

// ============================================================================
// Dead Letter Queue Helper
// ============================================================================

import { connection } from '../services/redis';

const DLQ_KEY = 'rinjani:dlq';
const DLQ_MAX_SIZE = 10_000;

export interface DLQEntry {
    queue: string;
    jobId: string;
    error: string;
    payload: Record<string, unknown>;
    failedAt: string;
    partialResults?: Record<string, unknown>;
}

/**
 * Push a failed job entry to the Dead Letter Queue (Redis list).
 * Trims to DLQ_MAX_SIZE to prevent unbounded growth.
 */
export async function sendToDeadLetterQueue(entry: DLQEntry): Promise<void> {
    try {
        await connection.lpush(DLQ_KEY, JSON.stringify(entry));
        await connection.ltrim(DLQ_KEY, 0, DLQ_MAX_SIZE - 1);
    } catch {
        // DLQ failure must never crash the caller — best-effort only
    }
}

/**
 * Retrieve recent DLQ entries for admin inspection.
 */
export async function getDLQEntries(limit = 50): Promise<DLQEntry[]> {
    const raw = await connection.lrange(DLQ_KEY, 0, limit - 1);
    return raw.map((s) => JSON.parse(s));
}
