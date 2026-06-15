# Declarative Feed Connector Engine

The engine replaces hand-written per-feed TypeScript parsers with a pure,
deterministic engine that runs declarative **manifests** (data, not code).
A manifest describes how to fetch a feed and map its records onto a canonical
entity; the engine validates per-record output against zod schemas grounded in
the `@rinjani/db` tables.

**Core rule:** the system (and the LLM draft-mapper) emits *manifests* — never
parser code. If you're writing a per-feed imperative parser, stop and author a
manifest instead.

This doc is the durable reference promoted out of the A0 assessment. For the
phase-by-phase build history, see the merged PRs #113–#123.

---

## 1. The parse seam

The engine plugs into exactly one point in the feed-sync pipeline.

**Dispatch:** `apps/api/src/services/feedSync/feedRegistry.ts`
- `FEED_REGISTRY` — the legacy map of `source → FeedHandler` (otx, cisa, threatfox, …).
- `resolveFeedHandler(source)` — the async dispatch the worker calls. Consults
  `FEED_ENGINE_ENABLED` + the `feed_manifest` table; returns an engine-backed
  handler only when both gates pass, otherwise the legacy registry entry.

**Worker call-site:** `apps/api/src/queues/workers/feedSyncWorker.ts`
```ts
const handler = await resolveFeedHandler(source);   // was: getFeedHandler(source)
result = await handler(options);
```

**The handler contract both paths satisfy:**
```ts
type FeedHandler = (opts?: FeedSyncOptions) => Promise<SyncResult>
// FeedSyncOptions = { limit?: number; since?: string }
// SyncResult — apps/api/src/services/feedSync/types.ts
//   carries normalized records under `indicators?: Array<{ id; value; type }>`
//   and per-record failures under `errors: string[]`
```

The engine handler (`engineHandler.ts`) wraps the pure engine in the three
side-effects it doesn't do itself — HTTP fetch, entity sink (drizzle upsert),
and `SyncResult` shaping — so everything downstream of the call-site
(auto-enrichment FlowProducer, decay machinery) is unchanged.

**Five legacy-fallback gates** (any one → legacy handler, never throws):
flag off · no active manifest · unsupported entity · manifest fails engine zod ·
DB lookup throws. This is why enabling the engine can't break a shipped feed.

---

## 2. `feeds_config` vs `feed_manifest` — the split

Two tables, deliberately disjoint. Confusing them causes duplicated state.

| Concern | Table | Owner |
|---|---|---|
| Scheduling, credentials, URL, format, enable/disable | `feeds_config` | shipped pre-engine; `/admin/feeds` + the BullMQ scheduler |
| Parser definition (the manifest body) | `feed_manifest` | the engine (migration 0059) |

`feed_manifest` does **not** re-store `enabled` / `cron` / `url` / `authKeyRef` /
`format` — those live in `feeds_config`. It owns only: `source`, `version`,
`entity`, `manifest` (jsonb), `is_active`, `created_by`, `created_at`,
`last_validated_at`, `last_validation_errors`.

**Versioning is immutable.** Each save is a new row with `version = max+1` for
the source. Rollback = activate an older version. Parity-diff = compare two
version rows. A partial unique index `(source) WHERE is_active` enforces
at-most-one-active-per-source; activation flips the flag in a transaction.

`created_by` is **TEXT, not a FK** to `users.id` — API-key auth uses
`key:xxxxxxxx` subjects (see `middleware/auth.ts`), not UUIDs, so a FK would
break every API-key write.

---

## 3. Entity enum + graph participation

The engine's `entity` enum targets the canonical `@rinjani/db` tables, **not
IOC-only**:

```
ioc | vulnerability | threat_actor | malware | campaign
  | course_of_action | infrastructure | technique | tool
```

`relationship` is a separate manifest construct (an edge between two entities),
not an entity. `galaxyClusters` is intentionally excluded (MISP-only, not a
Phase-2 STIX SDO).

**Graph-participation — the canonical answer to "does a new domain need a Neo4j
hydrate hook?"** Neo4j hydration fires on **relationship-table INSERT**, not
entity INSERT (`services/neo4j/syncRelationships.ts` — "single-relationship
side-effect on INSERT"). So an entity becomes a graph node only when some
relationship referencing it is inserted.

| Entity | Graph-participating? |
|---|---|
| `iocs`, `vulnerabilities`, `threat_actors`, `malware` | Yes |
| `campaigns`, `courses_of_action`, `infrastructure` | Yes (STIX SDOs) |
| `techniques`, `tools` | Yes (MITRE) |
| `galaxy_clusters` | No (MISP-only, not bridged) |

**For future domains (telco / on-chain / AI-vuln):** a new entity type that
participates in graph edges must land its hydrate hook on the **relationship-side
worker**, not the entity-insert path.

**Engine sink support is incremental.** `engineHandler.ts` dispatches on
`manifest.entity` to an entity-specific sink; `resolveFeedHandler`'s
`SUPPORTED_ENGINE_ENTITIES` set gates which entities reach the engine. Currently
`{ioc, vulnerability}`. Adding a new entity = one sink function + one set entry.

---

## 4. LLM draft-mapper + the `callLLM` pattern

`POST /v1/connectors/suggest` proposes a manifest from a sample payload.
`services/draftMapper.ts` reuses the shared provider abstraction — **do not add
a new LLM client.**

**Entry point:** `services/aiMiddleware/callLLM.ts`
```ts
callLLM(prompt, opts): Promise<LLMResponse>
// LLMResponse = { text; provider; model; tokensUsed?; latencyMs }
```
Providers cascade Gemini → OpenRouter → Ollama with deterministic fallback.
`jsonMode: true` is honored by all three (Gemini `responseMimeType`, OpenRouter
`response_format`, Ollama `format: json`) — pass it for structured output.

**Five never-stub guarantees** (every suggestion is a runnable manifest or an
explicit "couldn't map" — never a fake):
1. No provider reachable → empty skeleton (`enabled:false`, `mapping:{}`) + reason
2. Non-JSON output → skeleton + parse-error reason
3. Fails `FeedManifest` zod (incl. transform op outside the closed vocab) → skeleton
4. Wrong entity vs requested → skeleton + drift reason
5. Dry-run extracts 0 records → **the LLM's manifest** (not skeleton, so the
   operator can edit it) + the engine errors

The closed transform vocab (13 ops: trim, lower, upper, toNumber, toIso, default,
mapEnum, regexExtract, split, stripPrefix, coalesce, bucketize, prepend) is what
keeps LLM output executable + verifiable — it can't invent code paths.

New LLM surfaces ship with golden-output evals (mocked-LLM, in CI) — see
`__tests__/draft-mapper-golden.test.ts`.

---

## 5. Operating the engine

**Two gates, both required, to run a feed through the engine:**
1. `FEED_ENGINE_ENABLED=true` (env, global kill-switch) — wired through
   `docker-compose.yml`'s v3-api `environment:` block. Without the compose
   entry, setting it in `.env` does nothing (docker-compose only forwards
   explicitly-listed vars).
2. An **active** manifest for the source in `feed_manifest` — authored via the
   dashboard at `/admin/connectors/new` or `POST /v1/connectors` + `/activate`.

Until both flip for a source, that feed runs through its legacy handler — no
behavior change.

**Parity before retirement.** A feed is migrated one PR at a time, each gated by
a parity test that diffs engine output against a verbatim transcription of the
legacy handler on every detection-critical field (see `test/*-parity.test.ts`).
A legacy dispatch entry is retired only after prod parity — and the irregular
tail (multi-request pagination, 1:N fan-out, form-encoded bodies, UPDATE-only
sinks) stays on the legacy code path by design.

**Deploy checklist (a new workspace package or migration is involved):**
- Any new `packages/<x>` an app imports needs **two Dockerfile COPY lines**
  (package.json into the install layer, src into the source layer). `tsc`/`test`
  pass without it because they run against the host pnpm workspace; the
  container crash-loops at runtime with `ERR_MODULE_NOT_FOUND`. CI guards this
  via `scripts/check-dockerfile-deps.mjs`.
- After a schema migration: `db:apply` **inside the new container** (an old image
  doesn't have the new `.sql` on disk, so the runner reports "all applied"
  misleadingly), then restart v3-api to drop postgres-js's stale prepared-
  statement cache.

---

## Package layout

```
packages/feed-engine/          pure: no DB, no Redis, no network
  src/manifest.ts              FeedManifest zod + per-entity canonical schemas
  src/engine.ts                runEngine(manifest, payload): extract→map→transform→validate
  src/transforms.ts            closed registry of pure transform ops
  src/extract.ts               json (dot-path) / csv (quote-aware) / text (line-per-record)
  manifests/*.json             committed example manifests (threatfox, cisa-kev, openphish, urlhaus)
  test/*-parity.test.ts        per-feed parity gates

apps/api/src/services/
  connectorStore.ts            feed_manifest CRUD + activation transitions
  connectorPreview.ts          /preview + /test pure compute
  draftMapper.ts               LLM suggest + five never-stub guarantees
  feedSync/engineHandler.ts    fetch + runEngine + entity sink + SyncResult wrap
  feedSync/feedRegistry.ts     resolveFeedHandler gate chain

apps/api/src/routes/v1/connectors.ts   /v1/connectors/* (CRUD, suggest, preview, test)
```
