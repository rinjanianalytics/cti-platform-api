/**
 * SQL migration runner.
 *
 * `drizzle-kit migrate` only applies files registered in
 * `drizzle/meta/_journal.json`. We've authored a number of migrations
 * by hand (raw CREATE/ALTER SQL with idempotency guards) that aren't in
 * the journal. This runner picks up every `*.sql` file in the drizzle
 * directory, tracks what it has applied in a `__sql_migrations` table,
 * and runs only the unapplied files in deterministic alphabetical
 * order (which matches the `0001_`, `0002_` … convention).
 *
 * Usage:
 *   pnpm --filter @rinjani/db db:apply
 *   pnpm --filter @rinjani/db db:apply --baseline-until=30
 *
 * `--baseline-until=N` marks migrations 0000…NNNN_*.sql as applied
 * **without running them** — useful when adopting this runner against
 * an existing database where those migrations already ran via some
 * other path. Files with prefix > N still execute normally.
 *
 * Safe to re-run — already-applied files are skipped via the tracking
 * table. Failures abort the run; the offending file is logged.
 */

import { config as loadEnv } from 'dotenv';
import postgres from 'postgres';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// packages/db/src/scripts/apply-migrations.ts → packages/db/drizzle
const MIGRATIONS_DIR = join(__dirname, '..', '..', 'drizzle');

// Walk up from this file to find the repo root and load .env from there.
// `dotenv/config` defaults to CWD, which under `pnpm --filter` is the package
// dir — so we'd read the wrong (or missing) .env and silently connect to the
// localhost default. We replicate the worker's boot-env pattern.
//
// packages/db/src/scripts/apply-migrations.ts → repo root (three .. + one ..)
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const ENV_PATH = join(REPO_ROOT, '.env');
if (existsSync(ENV_PATH)) {
    loadEnv({ path: ENV_PATH });
    console.log(`✓ Loaded env from ${ENV_PATH}`);
} else {
    // Fall back to default dotenv loading (CWD-based) so this still works
    // for setups that put `.env` next to the package.
    loadEnv();
    console.warn(`⚠ ${ENV_PATH} not found — using CWD-based .env discovery.`);
}

const DATABASE_URL = process.env.DATABASE_URL
    || 'postgresql://postgres:postgres@localhost:5432/rinjani_v3';

/** Parse --baseline-until=NN from argv. Returns the highest migration
 *  prefix to mark as already-applied, or null if the flag isn't set. */
function parseBaselineFlag(): number | null {
    const arg = process.argv.slice(2).find(a => a.startsWith('--baseline-until='));
    if (!arg) return null;
    const raw = arg.split('=')[1];
    const n = parseInt(raw, 10);
    if (!Number.isFinite(n) || n < 0) {
        console.error(`Invalid --baseline-until value: ${raw} (expected non-negative integer)`);
        process.exit(2);
    }
    return n;
}

/** Extract the numeric prefix from a migration filename — `0032_foo.sql` → 32. */
function prefixOf(file: string): number | null {
    const m = file.match(/^(\d+)_/);
    return m ? parseInt(m[1], 10) : null;
}

async function main() {
    const baselineUntil = parseBaselineFlag();

    // Show a redacted form of the URL so the operator can spot
    // "wrong database" issues at a glance.
    const redacted = DATABASE_URL.replace(/:[^:@]+@/, ':****@');
    console.log(`Target: ${redacted}\n`);
    const sql = postgres(DATABASE_URL, { max: 1 });

    try {
        // Self-tracking table — stores the *file name* of every migration
        // that's been applied. Created on first run.
        await sql`
            CREATE TABLE IF NOT EXISTS __sql_migrations (
                name        TEXT PRIMARY KEY,
                applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `;

        const applied = new Set(
            (await sql<{ name: string }[]>`SELECT name FROM __sql_migrations`)
                .map(r => r.name),
        );

        const files = readdirSync(MIGRATIONS_DIR)
            .filter(f => f.endsWith('.sql'))
            .sort(); // 0001_, 0002_, …

        // --- Baseline mode -----------------------------------------------
        // Mark all files with numeric prefix ≤ baselineUntil as applied
        // without running them. Used once when adopting this runner on a
        // database that already has older migrations applied via another
        // path (raw psql, ad-hoc scripts, etc.).
        if (baselineUntil !== null) {
            const toBaseline = files.filter(f => {
                const p = prefixOf(f);
                return p !== null && p <= baselineUntil && !applied.has(f);
            });
            if (toBaseline.length === 0) {
                console.log(`✓ No baseline action needed — all migrations ≤ ${baselineUntil} are already tracked.`);
            } else {
                console.log(`Baselining ${toBaseline.length} migration(s) (marking as applied without running):`);
                for (const file of toBaseline) {
                    console.log(`  ⏭  ${file}`);
                    await sql.unsafe(
                        'INSERT INTO __sql_migrations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING',
                        [file],
                    );
                    applied.add(file);
                }
                console.log(`\n✓ ${toBaseline.length} migration(s) baselined.\n`);
            }
        }

        const pending = files.filter(f => !applied.has(f));

        if (pending.length === 0) {
            console.log(`✓ All ${files.length} migration(s) already applied.`);
            return;
        }

        console.log(`Applying ${pending.length} new migration(s):`);
        for (const file of pending) {
            console.log(`  → ${file}`);
            const path = join(MIGRATIONS_DIR, file);
            const content = readFileSync(path, 'utf-8').trim();
            if (!content) {
                console.warn(`    (empty file — recording as applied, skipping)`);
                await sql`INSERT INTO __sql_migrations (name) VALUES (${file})`;
                continue;
            }

            try {
                // Each file is a single transaction — if any statement
                // fails, the whole file rolls back. The tracking insert
                // is part of the same transaction so partial application
                // is impossible.
                await sql.begin(async (tx) => {
                    await tx.unsafe(content);
                    await tx.unsafe(
                        'INSERT INTO __sql_migrations (name) VALUES ($1)',
                        [file],
                    );
                });
                console.log(`    ✓ applied`);
            } catch (err) {
                console.error(`    ✗ failed:`, (err as Error).message);
                throw err;
            }
        }

        console.log(`\n✓ ${pending.length} migration(s) applied successfully.`);
    } finally {
        await sql.end();
    }
}

main().catch((err) => {
    console.error('Migration runner failed:', err);
    process.exit(1);
});
