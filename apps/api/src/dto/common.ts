/**
 * Shared DTO coercion helpers.
 *
 * Postgres + node-pg + OpenSearch passthrough produces several surprises
 * the client should never have to handle:
 *
 *   • COUNT(*)            → string (pg returns bigint as string)
 *   • NUMERIC columns     → string (precision-preserving — but JS only has
 *                          double, so we coerce here once)
 *   • timestamp without tz → JS Date or string depending on the driver path
 *
 * Every coercion here returns the JS-native type the API contract promises,
 * with consistent fallback (null/0) on bad input. These are the only
 * coercions we should be doing in the codebase — anything else is a sign
 * the DTO layer is missing a function.
 */

/** Coerce string/number/null → number | null. Empty / non-finite → null. */
export function toNumberOrNull(v: unknown): number | null {
    if (v === null || v === undefined) return null;
    if (typeof v === 'number') return Number.isFinite(v) ? v : null;
    if (typeof v === 'string') {
        const t = v.trim();
        if (!t) return null;
        const n = Number(t);
        return Number.isFinite(n) ? n : null;
    }
    return null;
}

/** Same as `toNumberOrNull` but defaults to 0 — for COUNT(*) and similar. */
export function toCount(v: unknown): number {
    return toNumberOrNull(v) ?? 0;
}

/** Date | string | null → ISO string | null. */
export function toIsoOrNull(v: unknown): string | null {
    if (v === null || v === undefined) return null;
    if (v instanceof Date) return Number.isFinite(v.getTime()) ? v.toISOString() : null;
    if (typeof v === 'string') {
        if (!v.trim()) return null;
        const d = new Date(v);
        return Number.isFinite(d.getTime()) ? d.toISOString() : null;
    }
    return null;
}
