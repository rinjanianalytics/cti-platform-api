/**
 * Env loader — must be the FIRST import in the worker entry points.
 *
 * ESM hoists all imports and evaluates them depth-first BEFORE the importing
 * module's body runs. If we call `dotenv.config()` in worker-entry.ts's body,
 * any transitively-imported module (e.g. apps/api/src/services/redis.ts)
 * has already constructed its connections using `process.env` defaults
 * because it ran during the import phase.
 *
 * Putting `config()` here, and importing this file FIRST in the entry,
 * forces env to load during the import phase too — before any consumer
 * reads `process.env`.
 */
import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '../../..');
config({ path: join(projectRoot, '.env') });

console.log('[Worker] Loaded DATABASE_URL:', process.env.DATABASE_URL ? '✅' : '❌',
            '· REDIS_URL:', process.env.REDIS_URL ? '✅' : '❌',
            '· REDIS_QUEUE_URL:', process.env.REDIS_QUEUE_URL ? '✅' : '❌');
