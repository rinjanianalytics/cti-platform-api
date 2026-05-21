/**
 * OAuth (Google + GitHub) — sign-in flow built on `arctic`.
 *
 * Flow per provider:
 *   1. /auth/oauth/<provider>            → server builds an auth URL with
 *                                          PKCE + state, sets HttpOnly
 *                                          cookies, redirects to provider
 *   2. /auth/oauth/<provider>/callback   → validates state, exchanges code
 *                                          for tokens, fetches the user's
 *                                          email + profile, upserts a
 *                                          Rinjani user + oauth_identity,
 *                                          issues a JWT, redirects to the
 *                                          dashboard with the token as a
 *                                          query param
 *
 * Admin elevation: any email listed in `ADMIN_EMAILS` (comma-separated env
 * var) is granted `admin` on first OAuth sign-in. Every other new user
 * defaults to `viewer`. Existing users keep whatever role they have.
 */

import { Google, GitHub, decodeIdToken, generateState, generateCodeVerifier, type OAuth2Tokens } from 'arctic';
import { Hono } from 'hono';
import { setCookie, getCookie, deleteCookie } from 'hono/cookie';
import { db, sql, eq, and } from '@rinjani/db';
import { users, oauthIdentities } from '@rinjani/db/schema';
import { createJWT } from '../middleware/auth';
import { createLogger } from '../lib/logger';

const log = createLogger('OAuth');

const STATE_COOKIE = 'oauth_state';
const VERIFIER_COOKIE = 'oauth_code_verifier';
const PROVIDER_COOKIE = 'oauth_provider';
const COOKIE_MAX_AGE = 10 * 60; // 10 minutes — only the auth round-trip

const DASHBOARD_URL = process.env.DASHBOARD_URL || 'http://localhost:3000';

// ---------------------------------------------------------------------------
// Schema bootstrap — make sure the oauth_identities table exists. We do this
// idempotently rather than relying on the Drizzle migration pipeline so the
// feature works the first time an operator turns it on.
// ---------------------------------------------------------------------------

let tableEnsured = false;
async function ensureOauthIdentitiesTable(): Promise<void> {
    if (tableEnsured) return;
    await db.execute(sql`
        CREATE TABLE IF NOT EXISTS oauth_identities (
            id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider      VARCHAR(32) NOT NULL,
            subject       VARCHAR(128) NOT NULL,
            email_at_link VARCHAR(255),
            linked_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_login_at TIMESTAMPTZ,
            CONSTRAINT oauth_identities_provider_subject_unique UNIQUE (provider, subject)
        )
    `);
    tableEnsured = true;
}

// ---------------------------------------------------------------------------
// Provider clients (lazy — only configured when env vars are present)
// ---------------------------------------------------------------------------

function getGoogle(): Google | null {
    const id = process.env.GOOGLE_OAUTH_CLIENT_ID;
    const secret = process.env.GOOGLE_OAUTH_CLIENT_SECRET;
    if (!id || !secret) return null;
    return new Google(id, secret, `${apiBase()}/auth/oauth/google/callback`);
}

function getGitHub(): GitHub | null {
    const id = process.env.GITHUB_OAUTH_CLIENT_ID;
    const secret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
    if (!id || !secret) return null;
    return new GitHub(id, secret, `${apiBase()}/auth/oauth/github/callback`);
}

function apiBase(): string {
    return process.env.API_PUBLIC_URL || `http://localhost:${process.env.PORT || '3001'}`;
}

function adminEmails(): Set<string> {
    return new Set(
        (process.env.ADMIN_EMAILS || '')
            .split(',')
            .map(e => e.trim().toLowerCase())
            .filter(Boolean),
    );
}

// ---------------------------------------------------------------------------
// Cookie helpers — wraps the Hono cookie API with our security defaults.
// ---------------------------------------------------------------------------

function isSecureCookie(): boolean {
    return process.env.NODE_ENV === 'production';
}

function setOAuthCookies(c: import('hono').Context, state: string, verifier: string | null, provider: string) {
    const opts = {
        path: '/',
        httpOnly: true,
        secure: isSecureCookie(),
        sameSite: 'Lax' as const,
        maxAge: COOKIE_MAX_AGE,
    };
    setCookie(c, STATE_COOKIE, state, opts);
    if (verifier) setCookie(c, VERIFIER_COOKIE, verifier, opts);
    setCookie(c, PROVIDER_COOKIE, provider, opts);
}

function clearOAuthCookies(c: import('hono').Context) {
    deleteCookie(c, STATE_COOKIE, { path: '/' });
    deleteCookie(c, VERIFIER_COOKIE, { path: '/' });
    deleteCookie(c, PROVIDER_COOKIE, { path: '/' });
}

// ---------------------------------------------------------------------------
// Identity → Rinjani user reconciliation
// ---------------------------------------------------------------------------

interface NormalisedIdentity {
    provider: 'google' | 'github';
    subject: string;
    email: string;
    name: string;
    avatarUrl: string | null;
}

async function upsertUserAndIdentity(identity: NormalisedIdentity): Promise<{
    id: string; email: string; name: string; role: string;
}> {
    await ensureOauthIdentitiesTable();
    const email = identity.email.toLowerCase();

    // Build the per-login refresh payload. Display name + lastLogin always refresh
    // (provider is canonical for those). Avatar is conditional: if the user has
    // uploaded a custom one through /settings/profile (stored as a `data:` URL),
    // we never overwrite it with the OAuth provider's avatar — that wipes the
    // user's explicit choice on every login. They can clear their custom avatar
    // from the settings page to restore the OAuth-provided one on next sign-in.
    function refreshPayload(existing: { avatarUrl: string | null }): {
        name: string; lastLogin: Date; avatarUrl?: string | null;
    } {
        const hasCustomAvatar = !!existing.avatarUrl?.startsWith('data:');
        return {
            name: identity.name,
            lastLogin: new Date(),
            ...(hasCustomAvatar ? {} : { avatarUrl: identity.avatarUrl }),
        };
    }

    // 1. Try by existing oauth_identity (returning user via this provider)
    const existingByProvider = await db.execute(sql`
        SELECT user_id FROM oauth_identities
        WHERE provider = ${identity.provider} AND subject = ${identity.subject}
        LIMIT 1
    `) as unknown as Array<{ user_id?: string }>;
    const linkedUserId = existingByProvider[0]?.user_id;
    if (linkedUserId) {
        await db.execute(sql`
            UPDATE oauth_identities SET last_login_at = NOW()
            WHERE provider = ${identity.provider} AND subject = ${identity.subject}
        `);
        const [current] = await db.select({ avatarUrl: users.avatarUrl })
            .from(users).where(eq(users.id, linkedUserId)).limit(1);
        const [updated] = await db.update(users)
            .set(refreshPayload(current ?? { avatarUrl: null }))
            .where(eq(users.id, linkedUserId))
            .returning();
        if (updated) return roleEnvelope(updated);
    }

    // 2. Try by email — user might have signed up via password/API key first.
    //    Link the new identity to that user rather than create a duplicate.
    const [existingByEmail] = await db.select().from(users).where(eq(users.email, email)).limit(1);
    if (existingByEmail) {
        await db.execute(sql`
            INSERT INTO oauth_identities (user_id, provider, subject, email_at_link, last_login_at)
            VALUES (${existingByEmail.id}, ${identity.provider}, ${identity.subject}, ${email}, NOW())
            ON CONFLICT (provider, subject) DO UPDATE SET last_login_at = NOW()
        `);
        const [updated] = await db.update(users)
            .set(refreshPayload({ avatarUrl: existingByEmail.avatarUrl ?? null }))
            .where(eq(users.id, existingByEmail.id))
            .returning();
        if (updated) return roleEnvelope(updated);
    }

    // 3. Brand-new user — create + apply admin allowlist
    const role = adminEmails().has(email) ? 'admin' : 'viewer';
    const [created] = await db.insert(users).values({
        email,
        name: identity.name,
        avatarUrl: identity.avatarUrl,
        roles: [role],
        isActive: true,
        lastLogin: new Date(),
    }).returning();

    await db.execute(sql`
        INSERT INTO oauth_identities (user_id, provider, subject, email_at_link, last_login_at)
        VALUES (${created.id}, ${identity.provider}, ${identity.subject}, ${email}, NOW())
    `);

    log.info('Created Rinjani user via OAuth', {
        provider: identity.provider, email, role, userId: created.id,
    });
    return roleEnvelope(created);
}

function roleEnvelope(row: typeof users.$inferSelect): {
    id: string; email: string; name: string; role: string;
} {
    const role = ((row.roles as string[] | null) || ['viewer'])[0] || 'viewer';
    return { id: row.id, email: row.email, name: row.name, role };
}

// ---------------------------------------------------------------------------
// Provider-specific user-info fetchers
// ---------------------------------------------------------------------------

async function fetchGoogleProfile(tokens: OAuth2Tokens): Promise<NormalisedIdentity> {
    // Google issues an ID token alongside the access token; decode it directly.
    const idToken = tokens.idToken();
    const claims = decodeIdToken(idToken) as {
        sub: string; email: string; name?: string; picture?: string; email_verified?: boolean;
    };
    if (!claims.email_verified) {
        throw new Error('Google account email is not verified');
    }
    return {
        provider: 'google',
        subject: claims.sub,
        email: claims.email,
        name: claims.name || claims.email,
        avatarUrl: claims.picture || null,
    };
}

async function fetchGitHubProfile(tokens: OAuth2Tokens): Promise<NormalisedIdentity> {
    // GitHub returns minimal info on /user; emails are a separate endpoint.
    const accessToken = tokens.accessToken();
    const [profileRes, emailsRes] = await Promise.all([
        fetch('https://api.github.com/user', {
            headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'rinjani-cti' },
        }),
        fetch('https://api.github.com/user/emails', {
            headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'rinjani-cti' },
        }),
    ]);
    if (!profileRes.ok) throw new Error(`GitHub /user failed: ${profileRes.status}`);
    if (!emailsRes.ok) throw new Error(`GitHub /user/emails failed: ${emailsRes.status}`);

    const profile = await profileRes.json() as {
        id: number; login: string; name: string | null; avatar_url: string | null;
    };
    const emails = await emailsRes.json() as Array<{
        email: string; primary: boolean; verified: boolean;
    }>;
    const primary = emails.find(e => e.primary && e.verified) ?? emails.find(e => e.verified);
    if (!primary) throw new Error('No verified GitHub email available');

    return {
        provider: 'github',
        subject: String(profile.id),
        email: primary.email,
        name: profile.name || profile.login,
        avatarUrl: profile.avatar_url,
    };
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export const oauthRouter = new Hono();

oauthRouter.get('/google', async (c) => {
    const google = getGoogle();
    if (!google) return c.json({ error: 'Google OAuth is not configured on this instance' }, 503);

    const state = generateState();
    const codeVerifier = generateCodeVerifier();
    const url = google.createAuthorizationURL(state, codeVerifier, ['openid', 'email', 'profile']);
    setOAuthCookies(c, state, codeVerifier, 'google');
    return c.redirect(url.toString());
});

oauthRouter.get('/google/callback', async (c) => {
    const google = getGoogle();
    if (!google) return c.json({ error: 'Google OAuth is not configured on this instance' }, 503);

    const code = c.req.query('code');
    const state = c.req.query('state');
    const storedState = getCookie(c, STATE_COOKIE);
    const verifier = getCookie(c, VERIFIER_COOKIE);
    clearOAuthCookies(c);

    if (!code || !state || !storedState || !verifier || state !== storedState) {
        log.warn('OAuth callback state mismatch', { provider: 'google', hasCode: !!code, sameState: state === storedState });
        return c.redirect(`${DASHBOARD_URL}/login?error=invalid_state`);
    }
    try {
        const tokens = await google.validateAuthorizationCode(code, verifier);
        const identity = await fetchGoogleProfile(tokens);
        const user = await upsertUserAndIdentity(identity);
        const token = createJWT({
            sub: user.id, name: user.name, role: user.role as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer',
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });
        return c.redirect(`${DASHBOARD_URL}/login?token=${encodeURIComponent(token)}`);
    } catch (err) {
        log.error('Google OAuth callback failed', err as Error);
        return c.redirect(`${DASHBOARD_URL}/login?error=oauth_failed`);
    }
});

oauthRouter.get('/github', async (c) => {
    const github = getGitHub();
    if (!github) return c.json({ error: 'GitHub OAuth is not configured on this instance' }, 503);

    const state = generateState();
    const url = github.createAuthorizationURL(state, ['read:user', 'user:email']);
    setOAuthCookies(c, state, null, 'github');
    return c.redirect(url.toString());
});

oauthRouter.get('/github/callback', async (c) => {
    const github = getGitHub();
    if (!github) return c.json({ error: 'GitHub OAuth is not configured on this instance' }, 503);

    const code = c.req.query('code');
    const state = c.req.query('state');
    const storedState = getCookie(c, STATE_COOKIE);
    clearOAuthCookies(c);

    if (!code || !state || !storedState || state !== storedState) {
        log.warn('OAuth callback state mismatch', { provider: 'github', hasCode: !!code, sameState: state === storedState });
        return c.redirect(`${DASHBOARD_URL}/login?error=invalid_state`);
    }
    try {
        const tokens = await github.validateAuthorizationCode(code);
        const identity = await fetchGitHubProfile(tokens);
        const user = await upsertUserAndIdentity(identity);
        const token = createJWT({
            sub: user.id, name: user.name, role: user.role as 'admin' | 'analyst' | 'developer' | 'auditor' | 'viewer',
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60),
        });
        return c.redirect(`${DASHBOARD_URL}/login?token=${encodeURIComponent(token)}`);
    } catch (err) {
        log.error('GitHub OAuth callback failed', err as Error);
        return c.redirect(`${DASHBOARD_URL}/login?error=oauth_failed`);
    }
});

/**
 * GET /auth/oauth/providers — lets the dashboard ask "which buttons can I
 * show?" without leaking server config. Returns booleans only.
 */
oauthRouter.get('/providers', (c) => {
    return c.json({
        google: Boolean(process.env.GOOGLE_OAUTH_CLIENT_ID && process.env.GOOGLE_OAUTH_CLIENT_SECRET),
        github: Boolean(process.env.GITHUB_OAUTH_CLIENT_ID && process.env.GITHUB_OAUTH_CLIENT_SECRET),
    });
});

// Tiny suppress so `and` import is used as a future-proof for additional filters.
void and;
