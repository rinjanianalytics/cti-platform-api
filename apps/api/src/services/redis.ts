/**
 * Redis Connection Service (Split Architecture)
 *
 * Provides two separate Redis connections:
 *   1. Queue connection  - persistent Redis (AOF) for BullMQ jobs
 *   2. Cache connection  - volatile Redis (LRU) for caching & rate limiting
 *
 * Environment Variables:
 *   REDIS_QUEUE_URL - Redis for BullMQ (default: redis://localhost:6380)
 *   REDIS_CACHE_URL - Redis for cache  (default: redis://localhost:6381)
 *   REDIS_URL       - Legacy fallback (both point here if split vars missing)
 *
 * Defaults match docker-compose.yml — `v3-redis-queue` exposes 6380 on the
 * host, `v3-redis-cache` exposes 6381. If you swap the compose file or run
 * Redis natively on 6379, set REDIS_URL / REDIS_CACHE_URL explicitly.
 */

import { Redis } from 'ioredis';
import { createLogger } from '../lib/logger';

const log = createLogger('Redis');

// ============================================================================
// Queue Connection (persistent — BullMQ)
// ============================================================================

const queueUrl = process.env.REDIS_QUEUE_URL
    || process.env.REDIS_URL
    || 'redis://localhost:6380';

export const connection = new Redis(queueUrl, {
    maxRetriesPerRequest: null, // Required for BullMQ
    enableReadyCheck: false,
    lazyConnect: false,
});

connection.on('connect', () => {
    log.info('Queue Redis connected', { url: queueUrl });
});

connection.on('error', (err) => {
    log.error('Queue Redis error', new Error(err.message));
});

// ============================================================================
// Cache Connection (volatile — caching, rate limiting)
// ============================================================================

const cacheUrl = process.env.REDIS_CACHE_URL
    || process.env.REDIS_URL
    || 'redis://localhost:6381';

export const cacheConnection = new Redis(cacheUrl, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    lazyConnect: false,
    retryStrategy: (times) => Math.min(times * 200, 5000),
});

cacheConnection.on('connect', () => {
    log.info('Cache Redis connected', { url: cacheUrl });
});

cacheConnection.on('error', (err) => {
    log.error('Cache Redis error', new Error(err.message));
});

// ============================================================================
// Public API
// ============================================================================

/**
 * Get Redis connection for BullMQ (persistent)
 */
export function getRedisConnection(): Redis {
    return connection;
}

/**
 * Get Redis connection for caching (volatile)
 */
export function getCacheConnection(): Redis {
    return cacheConnection;
}

/**
 * Check Redis health (both instances)
 */
export async function checkRedisHealth(): Promise<{
    queue: { connected: boolean; latency?: number };
    cache: { connected: boolean; latency?: number };
}> {
    const check = async (conn: Redis): Promise<{ connected: boolean; latency?: number }> => {
        try {
            const start = Date.now();
            await conn.ping();
            return { connected: true, latency: Date.now() - start };
        } catch {
            return { connected: false };
        }
    };

    const [queue, cache] = await Promise.all([
        check(connection),
        check(cacheConnection),
    ]);

    return { queue, cache };
}

/**
 * Graceful shutdown — close both connections
 */
export async function shutdownRedis(): Promise<void> {
    await Promise.allSettled([
        connection.quit(),
        cacheConnection.quit(),
    ]);
    log.info('All Redis connections closed');
}
