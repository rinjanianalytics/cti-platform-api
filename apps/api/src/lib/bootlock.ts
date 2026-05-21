/**
 * Cross-process boot lock.
 *
 * The API can run standalone (port 3001) AND embedded in the Gateway
 * (`GATEWAY_UNIFIED=1`, port 4000) at the same time. Both processes call
 * `bootServices()`, which independently boots schedulers, DB listeners,
 * embedding pipelines, etc. — doubling load on Postgres, OpenSearch, and
 * external APIs like Gemini.
 *
 * This module guards `bootServices()` with a Redis advisory lock so only the
 * first process to call `tryAcquireBootLock()` actually boots them. Other
 * processes log a clear "skipping" message and serve HTTP requests only.
 *
 * Lock semantics:
 * - Key:        `rinjani:bootlock:services`
 * - Value:      `<hostname>:<pid>:<short-uuid>` (unique per process)
 * - Acquire:    `SET key value NX PX 30000` — succeeds only if no holder
 * - Heartbeat:  every 10s, Lua-atomic CAS extends TTL only if we still own it
 * - Release:    Lua-atomic CAS DEL, only if we still own it
 * - Crash safe: TTL expires after 30s if holder dies without releasing
 *
 * Fail-open: if Redis is unavailable, we boot services anyway. Dev shouldn't
 * require Redis to launch the API for the first time.
 */

import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { getCacheConnection } from '../services/redis';
import { createLogger } from './logger';

const log = createLogger('BootLock');

const LOCK_KEY = 'rinjani:bootlock:services';
const TTL_MS = 30_000;
const HEARTBEAT_MS = 10_000;

const OWNER_ID = `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;

let heartbeatHandle: NodeJS.Timeout | null = null;

/**
 * Try to acquire the lock. Returns true if THIS process now owns it (and
 * therefore should boot background services). Returns false if another
 * process already holds it.
 *
 * On Redis errors, returns true (fail-open) so a missing Redis doesn't
 * silently disable background services.
 */
export async function tryAcquireBootLock(): Promise<boolean> {
    const r = getCacheConnection();
    try {
        const res = await r.set(LOCK_KEY, OWNER_ID, 'PX', TTL_MS, 'NX');
        if (res === 'OK') {
            log.info('Acquired bootlock — booting background services', { owner: OWNER_ID });
            startHeartbeat();
            return true;
        }
        const holder = await r.get(LOCK_KEY).catch(() => null);
        log.info('Bootlock held by another instance — skipping background services in this process', {
            holder: holder || 'unknown',
            self: OWNER_ID,
        });
        return false;
    } catch (err) {
        log.warn('Bootlock check failed — booting services anyway (assumes sole instance)', {
            error: (err as Error)?.message,
        });
        return true;
    }
}

/**
 * Read-only — who currently owns the bootlock? Useful for admin dashboards
 * that want to show "background services are running on host:pid". Returns
 * null if no one holds the lock or Redis is unavailable.
 */
export async function getBootLockOwner(): Promise<{
    owner: string | null;
    self: string;
    isUs: boolean;
}> {
    const r = getCacheConnection();
    try {
        const owner = await r.get(LOCK_KEY);
        return { owner, self: OWNER_ID, isUs: owner === OWNER_ID };
    } catch {
        return { owner: null, self: OWNER_ID, isUs: false };
    }
}

/** Release the lock — call from graceful shutdown. No-op if not owner. */
export async function releaseBootLock(): Promise<void> {
    stopHeartbeat();
    const r = getCacheConnection();
    // Atomic compare-and-delete: only release if we still own it.
    const lua = `
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        else
            return 0
        end
    `;
    try {
        const released = await r.eval(lua, 1, LOCK_KEY, OWNER_ID);
        if (released === 1) log.info('Released bootlock', { owner: OWNER_ID });
    } catch (err) {
        log.warn('Failed to release bootlock', { error: (err as Error)?.message });
    }
}

function startHeartbeat() {
    stopHeartbeat();
    heartbeatHandle = setInterval(refreshLock, HEARTBEAT_MS);
    // Don't keep the event loop alive just for the heartbeat.
    heartbeatHandle.unref?.();
}

function stopHeartbeat() {
    if (heartbeatHandle) {
        clearInterval(heartbeatHandle);
        heartbeatHandle = null;
    }
}

async function refreshLock() {
    const r = getCacheConnection();
    // Atomic CAS+PEXPIRE: only extend if we still hold the lock.
    const lua = `
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("PEXPIRE", KEYS[1], ARGV[2])
        else
            return 0
        end
    `;
    try {
        const ok = await r.eval(lua, 1, LOCK_KEY, OWNER_ID, String(TTL_MS));
        if (ok === 1) return;
        // Either someone stole it (clock-skew, manual del) or it expired.
        log.warn('Lost bootlock — stopping heartbeat; background services keep running but will not be re-claimed by us');
        stopHeartbeat();
    } catch (err) {
        // Don't kill the process on a single heartbeat failure — just log it.
        log.warn('Bootlock heartbeat error', { error: (err as Error)?.message });
    }
}
