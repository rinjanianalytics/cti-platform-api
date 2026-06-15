/**
 * Logger error-serialization tests.
 *
 * Covers the three error shapes the logger encounters in this repo:
 *   1. Native Error instances — standard happy path.
 *   2. postgres-js errors — plain objects with .code / .detail / .hint.
 *      Previously serialized as `'[object Object]'`; now formatted as
 *      `<code> <message> | detail=… | hint=…`.
 *   3. Legacy data-dict misuse — `log.error(msg, { error: 'X' })` calls
 *      from before the (msg, err, data) signature was documented. The
 *      logger now lifts the `error` field to a synthetic Error so the
 *      diagnostic reaches the log instead of being lost as
 *      `'[object Object]'`.
 *
 * Plus the proper 3-arg path: `log.error(msg, err, data)` works as before.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createLogger } from '../lib/logger';

const lines: string[] = [];
let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
    lines.length = 0;
    errorSpy = vi.spyOn(console, 'error').mockImplementation((line: string) => {
        lines.push(line);
    });
});

afterEach(() => {
    errorSpy.mockRestore();
});

function lastEntry() {
    expect(lines.length).toBeGreaterThan(0);
    return JSON.parse(lines[lines.length - 1]);
}

describe('logger.error — native Error instances', () => {
    const log = createLogger('Test');

    it('serializes Error name + message', () => {
        log.error('boom', new TypeError('not a number'));
        const entry = lastEntry();
        expect(entry.error).toMatchObject({
            name: 'TypeError',
            message: 'not a number',
        });
    });

    it('preserves Error.code when present (custom exceptions)', () => {
        const e = Object.assign(new Error('econn'), { code: 'ECONNREFUSED' });
        log.error('fetch failed', e);
        expect(lastEntry().error).toMatchObject({
            name: 'Error',
            message: 'econn',
            code: 'ECONNREFUSED',
        });
    });
});

describe('logger.error — postgres-js error shape (previously [object Object])', () => {
    const log = createLogger('Test');

    it('formats code + message + detail + hint into a single string', () => {
        // Shape that postgres-js throws — NOT an Error instance.
        const pgErr = {
            code: '42P01',
            message: 'relation "feed_manifest" does not exist',
            detail: 'table not yet created',
            hint: 'run db:apply to create it',
        };
        log.error('query failed', pgErr);
        const entry = lastEntry();
        expect(entry.error.name).toBe('PgError');
        expect(entry.error.message).toContain('42P01');
        expect(entry.error.message).toContain('relation "feed_manifest" does not exist');
        expect(entry.error.message).toContain('detail=table not yet created');
        expect(entry.error.message).toContain('hint=run db:apply to create it');
        expect(entry.error.code).toBe('42P01');
    });

    it('handles partial postgres-js shapes (only code + message)', () => {
        log.error('partial', { code: '42P07', message: 'already exists' });
        const entry = lastEntry();
        expect(entry.error.name).toBe('PgError');
        expect(entry.error.message).toBe('42P07 | already exists');
    });

    it('does NOT misclassify an empty object as a PgError (and does not log [object Object])', () => {
        // Empty object hits the data-dict-misuse branch in errorOrFatal first
        // (object, not Error, not pgError-shaped, no separate data arg). It
        // lifts to data with no synthetic error; the surviving log line must
        // never contain the literal `'[object Object]'`.
        log.error('empty err', {});
        const out = lines[lines.length - 1] ?? '';
        expect(out).not.toContain('[object Object]');
        expect(out).not.toContain('PgError');
    });
});

describe('logger.error — legacy data-dict misuse (the bug we are fixing)', () => {
    const log = createLogger('Test');

    it('lifts a string `error` field from a 2nd-arg data dict to a real diagnostic', () => {
        // The historic 10-call-site pattern that produced [object Object].
        log.error('migration failed', { error: 'relation does not exist' });
        const entry = lastEntry();
        // Synthetic Error wraps the message so it's actually visible.
        expect(entry.error.name).toBe('LegacyDataDictError');
        expect(entry.error.message).toBe('relation does not exist');
        // The data dict is preserved on the data field for completeness.
        expect(entry.data).toEqual({ error: 'relation does not exist' });
    });

    it('respects the proper (msg, err, data) signature — does not misclassify', () => {
        const realErr = new Error('actual failure');
        log.error('outer', realErr, { context: 'extra' });
        const entry = lastEntry();
        expect(entry.error.name).toBe('Error');
        expect(entry.error.message).toBe('actual failure');
        expect(entry.data).toEqual({ context: 'extra' });
    });

    it('lifts the data dict to data even when it has no `error` field (still no [object Object])', () => {
        log.error('weird', { somethingElse: 42 });
        const entry = lastEntry();
        // No `error` field → no synthetic Error → the entry has no `error` slot.
        expect(entry.error).toBeUndefined();
        // But the dict still surfaces under `data` so the diagnostic isn't lost.
        expect(entry.data).toEqual({ somethingElse: 42 });
        // The whole reason for this branch:
        expect(JSON.stringify(entry)).not.toContain('[object Object]');
    });
});

describe('logger.error — never logs the literal "[object Object]"', () => {
    const log = createLogger('Test');

    const scenarios: Array<{ name: string; arg: unknown }> = [
        { name: 'empty object', arg: {} },
        { name: 'data dict with error string', arg: { error: 'x' } },
        { name: 'postgres-js error', arg: { code: '42P01', message: 'x' } },
        { name: 'native Error', arg: new Error('x') },
        { name: 'plain string', arg: 'x' },
        { name: 'number', arg: 42 },
        { name: 'null', arg: null },
    ];

    for (const { name, arg } of scenarios) {
        it(`scenario: ${name}`, () => {
            log.error('test', arg);
            const out = lines[lines.length - 1] ?? '';
            // The whole point of this PR.
            expect(out).not.toContain('[object Object]');
        });
    }
});
