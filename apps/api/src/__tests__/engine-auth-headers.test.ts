/**
 * Tests for resolveAuthHeaders — the engine's auth-header wiring.
 *
 * Regression guard for the bug that would have silently broken the first
 * authenticated feed activation (ThreatFox) in prod: the manifest's `header`
 * field is the HTTP header NAME ("Auth-Key"), but the secret lives in the
 * THREATFOX_AUTH_KEY env var. The original code did `process.env[auth.header]`
 * = `process.env["Auth-Key"]` = undefined → no auth header sent → ThreatFox
 * returns no data. The parity tests never caught it because they run runEngine
 * against a static fixture and never exercise the fetch/auth path.
 *
 * `secretEnv` separates the two concerns: header name to send vs env var
 * holding the secret.
 */

import { describe, expect, it } from 'vitest';
import { resolveAuthHeaders } from '../services/feedSync/engineHandler';
import type { FeedManifest } from '@rinjani/feed-engine';

type Auth = FeedManifest['source']['auth'];

describe('resolveAuthHeaders — apiKeyHeader (the ThreatFox shape)', () => {
    it('reads the secret from secretEnv and sends it in the named header', () => {
        const auth = { type: 'apiKeyHeader', header: 'Auth-Key', secretEnv: 'THREATFOX_AUTH_KEY' } as Auth;
        const out = resolveAuthHeaders(auth, { THREATFOX_AUTH_KEY: 'sekret-123' });
        // The header NAME is "Auth-Key"; the VALUE comes from THREATFOX_AUTH_KEY.
        expect(out).toEqual({ 'Auth-Key': 'sekret-123' });
    });

    it('sends nothing when the secretEnv var is unset (no empty header)', () => {
        const auth = { type: 'apiKeyHeader', header: 'Auth-Key', secretEnv: 'THREATFOX_AUTH_KEY' } as Auth;
        const out = resolveAuthHeaders(auth, {}); // env missing the key
        expect(out).toEqual({});
    });

    it('REGRESSION: without secretEnv, falling back to header name finds nothing (documents the old bug)', () => {
        // Pre-fix manifest shape: header "Auth-Key" but no secretEnv. The code
        // falls back to process.env["Auth-Key"], which is never set — this is
        // exactly the silent failure the fix prevents. We assert the empty
        // result so the back-compat behaviour is explicit, not surprising.
        const auth = { type: 'apiKeyHeader', header: 'Auth-Key' } as Auth;
        const out = resolveAuthHeaders(auth, { THREATFOX_AUTH_KEY: 'sekret-123', 'Auth-Key': undefined });
        expect(out).toEqual({});
    });

    it('back-compat: works when the env var name DOES equal the header name', () => {
        // The narrow case where the old fallback happens to work.
        const auth = { type: 'apiKeyHeader', header: 'X-Api-Key' } as Auth;
        const out = resolveAuthHeaders(auth, { 'X-Api-Key': 'val' });
        expect(out).toEqual({ 'X-Api-Key': 'val' });
    });
});

describe('resolveAuthHeaders — bearer', () => {
    it('reads secretEnv and emits an Authorization: Bearer header', () => {
        const auth = { type: 'bearer', secretEnv: 'SOME_TOKEN' } as Auth;
        const out = resolveAuthHeaders(auth, { SOME_TOKEN: 'abc' });
        expect(out).toEqual({ Authorization: 'Bearer abc' });
    });

    it('back-compat: bearer can use header as the env var name', () => {
        const auth = { type: 'bearer', header: 'OTX_API_KEY' } as Auth;
        const out = resolveAuthHeaders(auth, { OTX_API_KEY: 'xyz' });
        expect(out).toEqual({ Authorization: 'Bearer xyz' });
    });

    it('sends nothing when the token env var is unset', () => {
        const auth = { type: 'bearer', secretEnv: 'SOME_TOKEN' } as Auth;
        expect(resolveAuthHeaders(auth, {})).toEqual({});
    });
});

describe('resolveAuthHeaders — none', () => {
    it('returns no headers regardless of env', () => {
        const auth = { type: 'none' } as Auth;
        expect(resolveAuthHeaders(auth, { ANYTHING: 'x' })).toEqual({});
    });
});

describe('resolveAuthHeaders — committed ThreatFox manifest wires through to a real env', () => {
    it('the shipped manifest auth block produces the Auth-Key header from THREATFOX_AUTH_KEY', async () => {
        // Load the actual committed manifest and assert its auth block resolves
        // correctly against the env shape the container provides (docker-compose
        // sets THREATFOX_AUTH_KEY from ABUSECH_API_KEY).
        const { readFileSync } = await import('node:fs');
        const { resolve, dirname } = await import('node:path');
        const { fileURLToPath } = await import('node:url');
        const here = dirname(fileURLToPath(import.meta.url));
        const manifestPath = resolve(here, '../../../../packages/feed-engine/manifests/threatfox.json');
        const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

        const out = resolveAuthHeaders(manifest.source.auth, { THREATFOX_AUTH_KEY: 'prod-key' });
        expect(out).toEqual({ 'Auth-Key': 'prod-key' });
    });
});
