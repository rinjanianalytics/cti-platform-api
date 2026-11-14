# Security Audit — 2026-05-27

Triggered by reports of the **2026-05-11 TanStack npm supply-chain compromise**
(CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx). Scope expanded to all dependency
advisories surfaced by `pnpm audit` across both backend and dashboard repos,
plus a manual review of middleware (cookie auth / JWT) and the vendored
`@rinjani/workbench-core` fork.

## Headline result

| Severity | Before | After | Change |
|----------|--------|-------|--------|
| critical | 2  | 1  | −1 |
| high     | 21 | 15 | −6 |
| moderate | 32 | 13 | −19 |
| low      | 4  | 1  | −3 |
| **total** | **59** | **30** | **−29 (49%)** |

Dashboard repo had 1 moderate (postcss) — unchanged, not exploitable in our
build profile.

## CVE-2026-45321 — TanStack Shai-Hulud worm

**Status: NOT compromised. Verified.**

42 `@tanstack/*` packages were poisoned on 2026-05-11 19:20–19:26 UTC with
`router_init.js` install-time malware that exfiltrates GitHub / npm / cloud
/ SSH credentials. The router family was the initial vector.

We vendored `@getworkbench/core` into `packages/workbench-core/` on 2026-05-26
and ran `pnpm install` multiple times since. That install window is *after*
the malicious versions were pulled from npm, so our installs picked clean
post-incident versions.

Cross-check (compromised range vs installed):

| Package                 | Compromised      | Patched (≥)  | Ours      | Status |
|-------------------------|------------------|--------------|-----------|--------|
| @tanstack/react-router  | 1.169.5–1.169.8  | 1.169.9      | 1.170.8   | ✓ clean |
| @tanstack/router-core   | 1.169.5–1.169.8  | 1.169.9      | 1.171.6   | ✓ clean |
| @tanstack/history       | 1.161.9–1.161.12 | 1.161.13     | 1.162.0   | ✓ clean |
| @tanstack/query-core    | n/a              | n/a          | 5.100.14  | ✓ confirmed clean family |
| @tanstack/react-query   | n/a              | n/a          | 5.100.14  | ✓ confirmed clean family |
| @tanstack/store         | n/a              | n/a          | 0.9.3     | ✓ confirmed clean family |
| @tanstack/react-store   | n/a              | n/a          | 0.9.3     | ✓ confirmed clean family |

Lockfile scanned for any 1.169.5–1.169.8 / 1.161.9–1.161.12 reference:
**none found**.

**Hardening:** added `pnpm.overrides` floors in root `package.json`:

```json
"pnpm": {
  "overrides": {
    "@tanstack/react-router": ">=1.169.9",
    "@tanstack/router-core":  ">=1.169.9",
    "@tanstack/history":      ">=1.161.13"
  }
}
```

These floors prevent a future loosened range or dependency-tree shift from
ever resolving the malicious 6-minute-window versions.

The dashboard repo has no `@tanstack/*` packages at all — confirmed.

## Direct-dependency advisories — fixed in this PR

### @hono/node-server 1.19.9 → 1.19.14 (HIGH — REACHABLE)
**Auth bypass for protected static paths via encoded slashes in serveStatic.**
[apps/api/src/routes/admin/queues.ts:56](apps/api/src/routes/admin/queues.ts#L56)
uses `@hono/node-server/serve-static` for the Bull Board adapter, which sits
behind `requireAuth + requireRole('admin')`. The bypass could let an attacker
walk through the auth gate with `%2f`-encoded path segments. Patched on
`apps/api`, `apps/gateway`, and via peer in `workbench-core`.

### hono 4.11.7 → 4.12.23 (HIGH advisory not reachable, moderate SSE/cookie ones are)
- HIGH: `serveStatic` arbitrary file access — **NOT reachable**, we don't
  import hono's own serveStatic (we use `@hono/node-server`'s).
- MODERATE: `writeSSE` CR/LF injection — reachable via
  [apps/api/src/routes/admin/activity.ts](apps/api/src/routes/admin/activity.ts)
  and [sseHelper.ts](apps/api/src/routes/streaming/sseHelper.ts), but data is
  always `JSON.stringify(msg)` (CR/LF escaped) with server-controlled `event`
  types. Low real-world exploitability.
- MODERATE: `setCookie` attribute injection — reachable via
  [services/oauth.ts](apps/api/src/services/oauth.ts), but `path` is hardcoded
  to `'/'` with no user-controlled `domain`. Not exploitable.
- MODERATE: `parseBody({dot:true})` prototype pollution — **NOT reachable**,
  we don't use parseBody.

Bumped anyway as defence-in-depth. Migration cost: **60 `c.req.param()`
typing fixes** across 10 files (hono ≥4.12 widened the return type to
`string | undefined`). All sites are route-pattern path params guaranteed
present by routing — fixed via either non-null assertion `!` (runtime no-op,
type-only) at the call site, or by widening the consuming helper's signature
(`parseIocId`, `getQueue`) so a missing id surfaces as a clean 400/404
instead of a downstream crash. See diff for full list.

### nodemailer 8.0.1 → 8.0.9 (MODERATE — low exploitability, easy bump)
SMTP command injection via CR/LF in transport name (EHLO/HELO). Transport
name isn't user-controlled in our usage; bumped for hygiene.

### protobufjs `>=7.5.5` via pnpm.overrides (CRITICAL transitive — patched)
Arbitrary code execution. Comes in deeply via
`@opentelemetry/auto-instrumentations-node → @opentelemetry/sdk-node →
@opentelemetry/exporter-logs-otlp-grpc → @grpc/grpc-js → @grpc/proto-loader`.
Override forces resolution to the patched version. Verified installed as
8.0.0.

## Middleware findings — hardened in this PR

### JWT signature comparison was timing-unsafe (`auth.ts:124`)
Plain `signature !== expectedSignature` leaks how many leading bytes matched
via response timing — the textbook way to forge an HMAC byte-by-byte. Even
over a network where jitter blunts the attack, it's best practice to use
constant-time comparison. **Fixed** to use `crypto.timingSafeEqual` with a
length-mismatch fast path (the length itself is not secret-dependent).

### JWT treated missing `exp` as "never expires" (`auth.ts:129`)
`if (payload.exp && payload.exp < now)` short-circuits on `!payload.exp`,
silently treating tokens with no `exp` claim as eternal. Verified all 8
`createJWT()` call sites in this codebase set `exp = now + 24h`, so no
legitimately-issued token lacks `exp`. **Fixed** to `if (!payload.exp ||
payload.exp < now) return null` — a token without `exp` was not minted by
this service and should not be honoured.

### Cookie-fallback parser (recently added) — clean
The `rinjani_token` cookie regex `/(?:^|;\s*)rinjani_token=([^;]+)/` is
bounded, no ReDoS. The cookie value goes through `verifyJWT` which now
verifies signature in constant time and rejects no-exp tokens.

### JWT does not honour the `alg` header — non-issue
`verifyJWT` always computes HS256, ignoring `alg` in the header — so the
classic `alg:none` attack is not exploitable. The shape is by-design.

## Findings deferred to follow-up PRs

### drizzle-orm 0.30.10 → ≥0.45.2 (HIGH — low reachability, high migration risk)
SQL injection via improperly escaped SQL identifiers. The vulnerable code
path requires passing user-controlled values as Drizzle identifiers
(`sql.identifier()` or dynamic column refs in the query builder).

Reachability check: all our `sql\`...\`` template usage interpolates Drizzle
**column objects** (compile-time constants, e.g. `${iocs.value}`), not user
input. All `sql.raw()` call sites use the project's own `escSql()` helper
(see [apps/api/src/lib/sanitize.ts](apps/api/src/lib/sanitize.ts)), which
bypasses Drizzle's identifier handling entirely. Low real-world reachability.

The bump 0.30 → 0.45 spans 15 minor versions with breaking API changes
across the entire DB layer (every schema file, every query). Bundling that
into a security PR would risk the kind of mistake we're trying to prevent.
Tracked as a dedicated migration.

### protobufjs additional advisories
8 more `protobufjs` advisories remain after the override (lower-severity
DoS / prototype-pollution variants). The OpenTelemetry chain pins specific
protobufjs versions via `@grpc/proto-loader`, so additional overrides need
per-parent verification. Tracked.

### Transitive criticals/highs that need per-parent verification
`minimatch` (ReDoS, deep in @bull-board/hono → ejs and drizzle-kit → glob),
`lodash` (`_.template` code injection, in @bull-board/api → redis-info),
`rollup` 4 arbitrary file write (in vitest → vite),
`fast-uri` path traversal (in @graphql-mesh/runtime → ajv),
`@opentelemetry/exporter-prometheus` process crash via malformed HTTP.

Each needs the parent package upgraded or an override checked against the
parent's peer constraint. Out of scope for this PR; tracked.

## Hono framework 4.12 migration notes (in this PR)

The `c.req.param('name')` return type widened to `string | undefined`.
Two patterns were used for fixes:

1. **Widen the consuming helper** when one helper services many call sites
   (`parseIocId` in `iocs.ts`, `getQueue` in `admin/queues.ts`). The helper
   now accepts `string | undefined` and surfaces a clean 400/404 on missing
   input rather than a downstream crash. *Defensive improvement, not just
   a type fix.*

2. **Non-null assertion `!`** at the call site when the param feeds an
   immediate inline use. The assertion is type-only (no runtime cost) and
   correct because every site is a route-pattern path param (e.g.
   `/users/:id`, `/queue/:name/job/:jobId`) — guaranteed present by routing.
   Comments at each site cite the route pattern.

Files touched (60 sites total, 10 files): `iocs.ts`, `yara.ts`,
`websocket/index.ts`, `admin/audit.ts`, `admin/federation.ts`,
`admin/feeds.ts`, `admin/queues.ts`, `admin/schedules.ts`,
`admin/users.ts`, `routes/opengate.ts`, `routes/taxii.ts`.

## Verification

- `pnpm install` clean (no peer-dep warnings)
- `pnpm --filter @rinjani/api exec tsc --noEmit` — 0 errors
- `pnpm --filter @rinjani/worker exec tsc --noEmit` — 0 errors
- `pnpm --filter @rinjani/gateway exec tsc --noEmit` — 0 errors
- `pnpm --filter @rinjani/workbench-core build` (Node 20) — UI 1.45MB / lib
  80KB, clean
- `pnpm audit` — 59 → 30 advisories

## What to do post-merge

- **Rotate operator credentials anyway** if any team member ran `pnpm install`
  on a machine that previously installed `@tanstack/*` between 2026-05-11
  19:20 UTC and the npm pull. Our installs were after the pull so we believe
  the tree is clean — but if anyone has a developer machine that did install
  any `@tanstack/*` during that window from this monorepo or elsewhere,
  treat that machine's credentials as compromised per advisory guidance.
- Watch for **patched parent packages** that would let us drop the
  `protobufjs` override. OpenTelemetry typically catches up within a release
  cycle.
- File tickets for the deferred items (drizzle-orm 0.30→0.45, transitive
  cleanups). The reachability analysis in this doc is the starting point for
  each.

## References

- [CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [TanStack incident follow-up (hardening)](https://tanstack.com/blog/incident-followup)
- [Snyk write-up — Mini Shai-Hulud](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [Wiz write-up](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)

---

# Security Audit — 2026-06-08 (follow-up)

Triggered by CI `pnpm audit` failure after Phase 4 PRs landed
(#48-#70). Closes the **deferred items** from the 2026-05-27 audit
(drizzle-orm 0.30 → 0.45 + transitive cleanups) plus three new
advisories that surfaced since (protobufjs 8.0.0 RCE, vitest UI file
disclosure, drizzle-orm SQLi).

## Headline result

| Severity | Before | After | Change |
|----------|--------|-------|--------|
| critical | 3  | 0  | −3 |
| high     | 19 | 0  | −19 |
| moderate | 16 | 0  | −16 |
| low      | 1  | 0  | −1 |
| **total** | **39** | **0** | **−39 (100%)** |

## What changed

**Direct dependency bumps** (security-driven only; no API changes
beyond what was already in the deferred list from 2026-05-27):

- `drizzle-orm` `^0.30.0` → `^0.45.2` across `packages/db`,
  `packages/core`, `apps/worker` — patches GHSA-gpj5-g38j-94v9 (SQL
  injection via improperly escaped identifiers). This was the
  highest-impact finding: prod direct dep.
- `drizzle-kit` `^0.21.0` → `^0.31.0` for compatibility with the new
  ORM major.
- `vitest` `^1.4.0` → `^4.1.0` across all four packages — patches
  GHSA-5xrq-8626-4rwp (arbitrary file read/exec when UI server is
  listening). Our test scripts use `vitest run` (no UI), so the
  exposure was nil in practice; bumping anyway to clear the audit.
- `turbo` `^2.0.0` → `^2.9.14` — patches GHSA-hcf7-66rw-9f5r (CSRF /
  session fixation in login callback) and GHSA-3qcw-2rhx-2726.
- `@opentelemetry/auto-instrumentations-node` `^0.69.0` → `^0.75.0`
  and `sdk-node` / `exporter-*-otlp-http` `^0.212.0` → `^0.217.0` —
  patches the Prometheus-exporter process-crash advisory (GHSA family)
  reaching us via three packages in the OTel ecosystem.

**Expanded `pnpm.overrides`** (transitive supply-chain floors):

| Package | Floor | Reason |
|---|---|---|
| `protobufjs` | `>=8.0.1` | Arbitrary code execution (GHSA-xq3m-2v4x-88gg) via OTel → grpc. Previous floor `>=7.5.5` no longer enough now that OTel ships 8.x. |
| `minimatch` | `>=9.0.5` | Three ReDoS advisories via drizzle-kit's glob chain. |
| `fast-uri` | `>=3.1.2` | Path traversal + host confusion via Hono → ajv. |
| `lodash` | `>=4.18.0` | Template code injection (GHSA-r5fr-rjxr-66jc) via bull-board + dagre. |
| `esbuild` | `>=0.25.0` | Dev-server cross-origin advisory. |
| `brace-expansion` | `>=2.0.3` | DoS via zero-step sequence. |
| `rollup` | `>=4.59.0` | Path traversal arbitrary file write. |
| `vite` | `>=5.4.16` | Path traversal in optimised-deps `.map` handling. |
| `yaml` | `>=2.8.3` | Stack overflow via deeply-nested collections. |
| `ws` | `>=8.20.1` | Uninitialised memory disclosure. |
| `uuid` | `>=11.1.1` | Missing buffer bounds check in v3/v5/v6. |

**Override comment block** in root `package.json` documents the
GHSA id + reachability path for every floor — keeps future-us from
asking "why is this here?" months from now.

## Verification

- `pnpm install` clean
- `pnpm --filter @rinjani/api exec tsc --noEmit` — 0 errors
- `pnpm --filter @rinjani/gateway exec tsc --noEmit` — 0 errors
- `pnpm --filter @rinjani/api exec vitest run` — 754/754 passing on
  vitest 4.1.8 (no test breakage from the vitest 1 → 4 major bump
  because we use the default config + `run` mode only — no UI, no
  experimental APIs)
- `pnpm audit` — 39 → 0 advisories

## What to do post-merge

- This audit cleared the deferred drizzle-orm + transitive items
  from 2026-05-27; nothing remains deferred from prior audits.
- The `pnpm audit` CI gate that was failing on PR #69/#70's runs
  should be green again — no follow-up CI work needed.

---

# Security Audit: 2026-11-14 (dependency refresh)

Triggered by GitHub Dependabot reporting 125 open alerts on `master`
(44 high, 70 moderate, 11 low). `pnpm audit` on the same commit counted
162 advisories across 38 packages, because it also lists advisories
Dependabot had not opened alerts for yet.

## Headline result

| Severity | Before | After |
|----------|--------|-------|
| critical | 1   | 0 |
| high     | 57  | 0 |
| moderate | 91  | 0 |
| low      | 13  | 0 |
| **total** | **162** | **0** |

## What changed

**Major upgrades of direct dependencies** (no patched release exists on
the old major):

| Package | From | To | Code impact |
|---|---|---|---|
| `zod` | 3.25 | 4.6.7 | See "zod 4 migration" below. |
| `nodemailer` | 8.0.9 | 10.5.0 | None. `createTransport`, `verify` and `sendMail` are unchanged. |
| `fast-xml-parser` | 4.5.6 | 5.12.1 | None. Same output on every live feed (see Verification). |
| `@hono/node-server` | 1.19.14 | 2.1.8 | None. `serve` and `serve-static` are unchanged for our use. |
| `@opentelemetry/*` | 0.217 / 2.5 | 0.301 / 3.1 | `NodeSDK` takes `metricReaders: [reader]` instead of `metricReader`. |
| `exa-js` | 2.3.0 | 2.28.0 | None. Removes the last copy of zod 3 from the tree. |

**Minor and patch bumps:** `hono` 4.13.18, `graphql-yoga` 5.24.6,
GraphQL Mesh and `@graphql-tools/*` in the gateway, `vitest` 4.1.12,
`vite` 6.4.6, `react-router-dom` 7.18.5.

**`pnpm.overrides`:** five existing floors raised, thirteen ranged
entries added for transitive packages. The comment block in the root
`package.json` lists each one and the parent that pulls it in.

## zod 4 migration

- `z.record(value)` is now `z.record(z.string(), value)`.
- Object schemas that used `.default({})` to fill nested defaults now
  use `.prefault({})`, which is the zod 4 name for that behavior.
- `ZodError.errors` is now `ZodError.issues`.
- `required_error` and `errorMap` options are now the `error` option.
- `z.string().uuid()` became `z.string().guid()`. zod 4's `uuid()`
  rejects IDs whose version and variant digits are not RFC 9562 values.
  `guid()` accepts any 8-4-4-4-12 hex string, which is what zod 3
  accepted, so no ID that validated before is rejected now.

**Visible to API clients:** the `details` array of a `VALIDATION_ERROR`
response carries zod's issue objects. zod 4 renames some issue codes
(for example `invalid_string` is now `invalid_format`) and rewords the
default messages. Status codes and the `error.code` field are the same.

## Not upgraded, on purpose

- `graphql-yoga` 6 and `@graphql-tools/schema` 11 need Node 22. The
  image and CI run Node 20, so these stay on their previous majors,
  which have patched releases.
- `@xenova/transformers` has no release that uses a patched `sharp`.
  An override moves its `sharp` to 0.35.5. Local embedding does not
  use image code, and it still produces 384-dimension vectors.

## Verification

- `pnpm audit`: 0 advisories.
- `tsc --noEmit` for api, worker and gateway: 0 errors.
- `pnpm test`: 1,597 tests pass (api 1,202, feed-engine 381, gateway 14), 1 skipped as before.
- `pnpm lint`, `pnpm build`, `scripts/check-dockerfile-deps.mjs`: pass.
- XML parser: version 4.5.6 and 5.12.1 give identical output on the
  eight intel and telco feeds and the OFAC SDN list, each parsed with
  the options its feed handler uses.
- `docker build` passes on `node:20-slim`. The container started
  against a fresh Postgres 16 (52 migrations applied) and Redis 8:
  `/healthz` and `/readyz` return 200, authenticated REST reads and
  writes work, invalid bodies return 400, GraphQL answers, and the
  queue dashboard serves its static files.
- OpenTelemetry starts and records spans with an OTLP endpoint set.

Not verified: routes that need OpenSearch or Neo4j, a real SMTP
server, and a real OTLP collector.

## What to do post-merge

- Rebuild and redeploy the API image. No migration is involved.
- Node 20 is past its end of life. The image and CI moved to Node 22
  in a follow-up change, which unblocks `graphql-yoga` 6.
