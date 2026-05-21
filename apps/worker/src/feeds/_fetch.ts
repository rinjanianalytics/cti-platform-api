/**
 * Shared HTTP fetch with retry-on-transient-error.
 *
 * Used by every feed-sync handler so a single Gateway-Timeout / 503 from an
 * upstream provider doesn't blow up the whole sync cycle. Permanent errors
 * (4xx except 429) fail fast — no point retrying a 401 / 403 / 404.
 *
 *   - Retries: 429 + all 5xx + network/abort errors
 *   - Backoff: 1s → 2s → 4s (max 8s)
 *   - Max attempts: 3 (configurable)
 *
 * Logs each retry via console.warn so the worker output makes the cause and
 * timing visible without flipping to debug level.
 */

export interface RetryOptions {
    /** Provider name for log messages, e.g. 'MalwareBazaar'. */
    name: string;
    /** Total attempts including the first. Default 3. */
    maxRetries?: number;
}

export async function fetchWithRetry(
    url: string,
    init: RequestInit,
    opts: RetryOptions,
): Promise<Response> {
    const { name, maxRetries = 3 } = opts;

    let lastError: Error | null = null;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const res = await fetch(url, init);
            if (res.ok) return res;

            // 4xx (except 429) is permanent — bad key, bad request, expired token.
            // Fail fast so we don't waste 7 seconds of backoff on a misconfig.
            if (res.status >= 400 && res.status < 500 && res.status !== 429) {
                throw new Error(`${name} API error: ${res.status} ${res.statusText}`);
            }

            // 429 / 5xx — transient. Back off and try again.
            lastError = new Error(`${name} API error: ${res.status} ${res.statusText}`);
            if (attempt < maxRetries - 1) {
                await backoff(name, lastError, attempt, maxRetries);
            }
        } catch (err) {
            // If the catch caught a permanent-status throw above, propagate it.
            const msg = (err as Error).message;
            if (/API error: 4(?!29)\d\d /.test(msg)) throw err;

            // Otherwise treat as transient (network error, abort, timeout, …).
            lastError = err as Error;
            if (attempt < maxRetries - 1) {
                await backoff(name, lastError, attempt, maxRetries);
            }
        }
    }

    throw lastError ?? new Error(`${name} request failed after ${maxRetries} attempts`);
}

async function backoff(name: string, err: Error, attempt: number, total: number): Promise<void> {
    const waitMs = Math.min(1000 * Math.pow(2, attempt), 8000);
    console.warn(`[${name}] ${err.message} — retrying in ${waitMs}ms (attempt ${attempt + 1}/${total})`);
    await new Promise(r => setTimeout(r, waitMs));
}
