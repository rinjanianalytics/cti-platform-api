/**
 * Environment Validation — Fail-Fast Startup Check
 *
 * Validates critical environment variables at import time.
 * Crashes on missing required vars; warns on missing optional vars.
 *
 * Usage:
 *   import { env } from '../lib/env';
 *   console.log(env.DATABASE_URL);
 */

// Load .env from the monorepo root before reading process.env.
// Resolved relative to this file (apps/api/src/lib/env.ts → ../../../.. = repo root).
// In containers, .env is absent and dotenv is a no-op; real vars come from compose.
import { config as loadDotenv } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
const __envFilename = fileURLToPath(import.meta.url);
const __envProjectRoot = join(dirname(__envFilename), '../../../..');
loadDotenv({ path: join(__envProjectRoot, '.env') });

import { z } from 'zod';
import { createLogger } from './logger';

const log = createLogger('Env');

// ============================================================================
// Schema
// ============================================================================

const EnvSchema = z.object({
    // ── Required ────────────────────────────────────────────────────────
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    REDIS_QUEUE_URL: z.string().default('redis://localhost:6380'),
    REDIS_CACHE_URL: z.string().default('redis://localhost:6379'),

    // ── Server ──────────────────────────────────────────────────────────
    PORT: z.coerce.number().int().min(1).max(65535).default(3001),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

    // ── Optional services (warn if missing) ─────────────────────────────
    OPENAI_API_KEY: z.string().optional(),
    NEO4J_URI: z.string().optional(),
    NEO4J_USER: z.string().optional(),
    NEO4J_PASSWORD: z.string().optional(),
    OPENSEARCH_URL: z.string().optional(),
    EXA_API_KEY: z.string().optional(),
    JWT_SECRET: z.string().min(16, 'JWT_SECRET must be at least 16 characters'),
});

type Env = z.infer<typeof EnvSchema>;

// ============================================================================
// Parse & Validate
// ============================================================================

function validateEnv(): Env {
    const result = EnvSchema.safeParse(process.env);

    if (!result.success) {
        const errors = result.error.issues
            .map(i => `  • ${i.path.join('.')}: ${i.message}`)
            .join('\n');
        log.error(`Environment validation failed:\n${errors}`);
        throw new Error(`Missing or invalid environment variables:\n${errors}`);
    }

    const env = result.data;

    // Warn on missing optional services
    const optionalChecks: [string, string | undefined, string][] = [
        ['OPENAI_API_KEY', env.OPENAI_API_KEY, 'AI analysis will be disabled'],
        ['NEO4J_URI', env.NEO4J_URI, 'Graph database features disabled'],
        ['OPENSEARCH_URL', env.OPENSEARCH_URL, 'Full-text search limited to Postgres'],
        ['EXA_API_KEY', env.EXA_API_KEY, 'Nexus web intelligence disabled'],
    ];

    for (const [name, value, impact] of optionalChecks) {
        if (!value) {
            log.info(`Optional: ${name} not set — ${impact}`);
        }
    }

    log.info('Environment validated', { nodeEnv: env.NODE_ENV, port: env.PORT });
    return env;
}

export const env = validateEnv();
