# Changelog

All notable changes to **cti-platform-api** are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); we use Conventional
Commits in our git log so most entries can be derived from `git log --pretty=%s`.

## [Unreleased]

_(Add entries here as work lands on `master`. Cut a new dated section when tagging a release.)_

### Security
- **Dependency refresh (2026-11-14)**: cleared all 162 `pnpm audit`
  advisories (125 Dependabot alerts). Major upgrades: `zod` 3 to 4,
  `nodemailer` 8 to 10, `fast-xml-parser` 4 to 5, `@hono/node-server`
  1 to 2, OpenTelemetry SDK 0.217 to 0.301. See
  [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

### Changed
- `VALIDATION_ERROR` responses: the `details` array now carries zod 4
  issue objects. Some issue codes and default messages differ from
  zod 3. Status codes and `error.code` are unchanged.

---

## [3.0.0] — 2026-05-28

First public release. Consolidates roughly five months of private work into
a tagged baseline. Anyone landing on this repo via the cti-platform-api
slug can clone, run `pnpm install && docker compose up -d && pnpm dev`, and
get a working CTI backend serving CISA / NVD / CVE.org / MITRE / OTX / MISP /
five abuse.ch feeds, plus the embedded Workbench pipeline UI.

### Security
- **Pre-public history scrub** — removed a `.env` file from three commits
  including the initial commit via `git filter-repo`. Rotated all 60+
  exposed secrets in running services. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md).
- **TanStack CVE-2026-45321 (Mini Shai-Hulud worm)** — verified clean
  (installed versions sit above the malicious 6-minute-window range);
  hardened with `pnpm.overrides` floors on `@tanstack/react-router`,
  `@tanstack/router-core`, `@tanstack/history`, and `protobufjs`.
- **Direct-dep bumps** — `@hono/node-server` 1.19.9 → 1.19.14 (HIGH auth
  bypass via encoded slashes in serveStatic, reachable through the Bull
  Board mount), `hono` 4.11.7 → 4.12.23 (defence-in-depth + 60 c.req.param
  typing fixes), `nodemailer` 8.0.1 → 8.0.9.
- **JWT middleware hardening** — constant-time signature compare with
  `crypto.timingSafeEqual` (was leaking via `!==`), reject tokens with
  missing `exp` (was treating them as eternal).
- **SQL-injection sweep on IOC handlers** + auth handler hardening from
  earlier in the cycle.

### Added
- **Embedded Workbench BullMQ dashboard** at `/admin/workbench` — vendored
  fork at `packages/workbench-core/` (pinned to upstream `5e1bbf30`, MIT
  preserved) with scheduler edit / disable / run-now actions delegating
  to our `reconcileScheduledJob` control plane. See
  [packages/workbench-core/VENDOR.md](packages/workbench-core/VENDOR.md).
- **FlowProducer pilot** in `feedSyncWorker` — each sync builds one parent
  batch in `feed-batch` plus N enrichment children in `ioc-enrichment`;
  parent stamps `feed_sync_runs.enriched_at` when all children settle.
- **cve.org cvelistV5** as the primary CVE ingest (hours-fresh, not days
  like NVD). NVD kept as a CVSS-score backfill.
- **Activity-scored threat-actor watchlist** — composite of feed mentions,
  recency, IOC count, MITRE association count, replacing pure
  `last_seen DESC` ordering.
- **Bootlock reclaim** — non-owner processes now poll every 30s (matching
  TTL) and pick up the lock when the previous holder dies without
  graceful release, so background services don't get orphaned after
  `tsx watch` reloads.
- **Service-health aggregator** at `GET /admin/services` — datastore
  probes, BullMQ queue depths, worker liveness, bootlock state, feed-sync
  results, LLM provider configuration, OSV/NVD enrichment status — one
  round trip.
- **Worker process merged into API** — single `pnpm dev` runtime, gated
  by Redis bootlock so concurrent api+gateway processes don't both
  schedule. `apps/worker` kept as a build target for the `dev:standalone`
  daemon and one-off `sync:*` CLIs.
- **OAuth sign-in** for Google + GitHub, with admin elevation via
  `ADMIN_EMAILS` env var.
- **Cookie-based auth fallback** in `optionalAuth` middleware — embedded
  same-origin UIs (Workbench at `/admin/workbench`) ride the dashboard's
  `rinjani_token` cookie without needing their own auth layer.
- **Federation layer** — tenant schemas, peer connections, trust-level
  scoring (`/admin/federation/*`).
- **TAXII 2.1 server** for downstream STIX consumers.
- **GraphQL** via Pothos at `/graphql`, plus REST v1/v2 and WebSocket
  subscriptions.
- **Migration 0038** — adds `enriched_at`, `enrichment_children_total`,
  `enrichment_children_done` to `feed_sync_runs` for FlowProducer's
  parent/child accounting.
- **Migration 0037** — moves `feed_sync_runs` from runtime DDL to a
  proper Drizzle migration file.

### Changed
- **Aligned dep versions** across `apps/api` + `apps/worker` + `apps/gateway`:
  `bullmq` ^5.77.3, `ioredis` ^5.10.1. Avoids two BullMQ copies in the tree.
- **NVD API key resolution** unified across all 7 call sites — accepts
  both `NVD_API_KEY` (canonical, matches NIST's portal) and `CVE_API_KEY`
  (legacy). Documented in `.env.example`. Without a key, NVD throttles
  to 5 req/30s; with one, ~50 req/30s — a 9× throughput improvement that
  was silently unavailable when half the code only read `CVE_API_KEY`.
- **Scheduler reconcile** dedupes zombie repeatables by name (BullMQ
  `getRepeatableJobs()` returns `id: undefined` in current versions,
  silently breaking id-based dedup).
- **CVE.org sync** now indexes to OpenSearch directly rather than waiting
  on the PG NOTIFY listener, so new CVEs are searchable in seconds.

### Fixed
- **Overview correctness** — vulnerability severity case sensitivity,
  MITRE total dedup, KEV filter actually filtering, OAuth avatar
  preservation.
- **Playbook execute** returns the full row so the client surfaces real
  status instead of `undefined`.
- **Gemini embedding rate-limit** bucket sizing; OpenRouter Llama 70b
  default.
- **URLhaus** sync uses GET (was POST, silently failing).
- **Neo4j health probe** in `/admin/services` now calls the real export
  name (`checkNeo4jHealth`, not the non-existent `checkHealth`) — was
  always reporting "no health probe".

### Infrastructure
- Public-ready repo polish — added `LICENSE` (MIT), `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue + PR templates,
  `CODEOWNERS`. Repo renamed from `v3-backend-api-rinjani` to
  `cti-platform-api` (paired with `cti-platform-dashboard`).
- Backend CI runs lint + typecheck + tests on push/PR.

[Unreleased]: https://github.com/rinjanianalytics/cti-platform-api/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/rinjanianalytics/cti-platform-api/releases/tag/v3.0.0
