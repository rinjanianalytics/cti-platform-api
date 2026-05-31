/**
 * Test Setup
 * 
 * Configure test environment and global utilities.
 */

import { beforeAll, afterAll, vi } from 'vitest';

// Base URL for API tests
export const API_BASE_URL = 'http://localhost:3001';

// Test API key (for authenticated requests)
export const TEST_API_KEY = 'test-api-key-for-integration-tests';

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// Global setup — flush rate-limit keys so previous runs don't interfere
beforeAll(async () => {
    process.env.NODE_ENV = 'test';

    // Flush rate-limit counters via Redis
    try {
        // One extra `..` because setup.ts moved into `integration/`
        const { cacheConnection } = await import('../../services/redis');
        const keys = await cacheConnection.keys('rjn:rl:*');
        if (keys.length > 0) {
            await cacheConnection.del(...keys);
        }
    } catch {
        // Redis may not be available in unit-test-only runs
    }
});

afterAll(() => {
    // Cleanup
});

/**
 * Helper to make API requests.
 * Tests use 429-tolerant assertions to handle rate limiting.
 */
export async function apiRequest(
    path: string,
    options: RequestInit = {}
): Promise<Response> {
    const url = `${API_BASE_URL}${path}`;

    return fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
    });
}

/**
 * Helper to make authenticated API requests
 */
export async function authApiRequest(
    path: string,
    options: RequestInit = {}
): Promise<Response> {
    return apiRequest(path, {
        ...options,
        headers: {
            'X-API-Key': TEST_API_KEY,
            ...options.headers,
        },
    });
}

/**
 * Parse JSON response with error handling
 */
export async function parseResponse<T = unknown>(response: Response): Promise<T> {
    const text = await response.text();
    try {
        return JSON.parse(text);
    } catch {
        throw new Error(`Invalid JSON response: ${text}`);
    }
}
