/**
 * Opengate API Routes
 * 
 * Partner/Customer subscription and API key management.
 * Uses existing apiKeys table from users schema.
 */

import { Hono } from 'hono';
import { createHash, randomBytes } from 'crypto';
import { and, db, desc, eq, sql } from '@rinjani/db';
import { apiKeys, users } from '@rinjani/db/schema';
import { requireAuth, requireRole } from '../middleware/auth';
import { NotFoundError } from '../lib/errors';
import { CreateApiKeySchema } from '../lib/schemas';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate a secure API key with prefix
 */
function generateApiKey(): { key: string; hash: string; prefix: string } {
    const key = `octi_${randomBytes(32).toString('hex')}`;
    const hash = createHash('sha256').update(key).digest('hex');
    const prefix = key.substring(0, 12);
    return { key, hash, prefix };
}

/**
 * Hash an API key for storage
 */
function hashApiKey(key: string): string {
    return createHash('sha256').update(key).digest('hex');
}

// ============================================================================
// Router
// ============================================================================

const opengate = new Hono();

// ============================================================================
// Public Endpoints
// ============================================================================

/**
 * Get API info
 */
opengate.get('/', (c) => {
    return c.json({
        name: 'Opengate API',
        version: '1.0.0',
        description: 'Partner/Customer API key management',
        endpoints: {
            register: 'POST /register',
            profile: 'GET /profile',
            usage: 'GET /usage',
            keys: 'GET/POST/DELETE /keys',
        },
    });
});

/**
 * Generate API key for authenticated user
 */
opengate.post('/keys', requireAuth, async (c) => {
    const user = c.get('user');
    const body = CreateApiKeySchema.parse(await c.req.json());

    // Generate new API key
    const { key, hash, prefix } = generateApiKey();

    // Save to database using userId (existing schema)
    const [newKey] = await db.insert(apiKeys)
        .values({
            userId: user.id,
            keyHash: hash,
            keyPrefix: prefix,
            name: body.name || 'API Key',
        })
        .returning();

    return c.json({
        success: true,
        data: {
            id: newKey.id,
            key: key,     // Only shown once!
            prefix: prefix,
            name: newKey.name,
            createdAt: newKey.createdAt,
        },
        warning: 'Save your API key - it will not be shown again!',
    });
});

/**
 * List API keys for authenticated user
 */
opengate.get('/keys', requireAuth, async (c) => {
    const user = c.get('user');

    const keys = await db.select({
        id: apiKeys.id,
        name: apiKeys.name,
        prefix: apiKeys.keyPrefix,
        lastUsedAt: apiKeys.lastUsedAt,
        expiresAt: apiKeys.expiresAt,
        createdAt: apiKeys.createdAt,
    })
        .from(apiKeys)
        .where(eq(apiKeys.userId, user.id))
        .orderBy(desc(apiKeys.createdAt));

    return c.json({
        success: true,
        data: keys,
    });
});

/**
 * Revoke an API key
 */
opengate.delete('/keys/:id', requireAuth, async (c) => {
    const user = c.get('user');
    const keyId = c.req.param('id')!; // route-guaranteed by :id pattern

    // Check key belongs to user
    const [key] = await db.select()
        .from(apiKeys)
        .where(and(
            eq(apiKeys.id, keyId),
            eq(apiKeys.userId, user.id)
        ))
        .limit(1);

    if (!key) {
        throw new NotFoundError('API key', keyId);
    }

    // Delete the key
    await db.delete(apiKeys).where(eq(apiKeys.id, keyId));

    return c.json({
        success: true,
        message: 'API key revoked successfully',
    });
});

/**
 * Get user profile (stub - uses auth user data)
 */
opengate.get('/profile', requireAuth, async (c) => {
    const user = c.get('user');

    // Get key count
    const keysResult = await db.select({ count: sql<number>`count(*)` })
        .from(apiKeys)
        .where(eq(apiKeys.userId, user.id));

    return c.json({
        success: true,
        data: {
            id: user.id,
            email: user.name,  // Use name as fallback
            name: user.name,
            role: user.role,
            apiKeyCount: Number(keysResult[0]?.count ?? 0),
        },
    });
});

/**
 * Get usage statistics (stub)
 */
opengate.get('/usage', requireAuth, async (c) => {
    const user = c.get('user');

    return c.json({
        success: true,
        data: {
            userId: user.id,
            period: 'current_month',
            requestsTotal: 0,
            requestsRemaining: 1000,
            quotaLimit: 1000,
            lastRequest: null,
        },
    });
});

// ============================================================================
// Admin Endpoints
// ============================================================================

/**
 * List all users with API keys (admin only)
 */
opengate.get('/admin/users', requireAuth, requireRole('admin'), async (c) => {
    const allUsers = await db.select({
        id: users.id,
        email: users.email,
        name: users.name,
        isActive: users.isActive,
        createdAt: users.createdAt,
    })
        .from(users)
        .orderBy(desc(users.createdAt));

    return c.json({
        success: true,
        data: allUsers,
    });
});

export default opengate;
