# Roadmap

> Status: **aspirational, not contractual.** This is a single-maintainer
> project (with Claude Code as a pair-programming partner). Dates are
> targets, not commitments. Phases get re-ordered when real-world usage
> tells us what matters and what doesn't.

Last reviewed: **2026-06-05**.

## Status legend

| Marker | Meaning |
|---|---|
| 🟢 Shipped | In `master`, documented, used in production |
| 🟡 In flight | Branch open or active design |
| ⚪ Planned | Scoped, not started |
| 🔵 Considering | On the table, awaiting signal from users |

## Guiding principles

1. **Signal-per-engineering-hour first.** A single enricher that filters
   30% of IOCs as benign scanner noise beats a beautiful workflow editor.
2. **Read the data, then write the feature.** Every phase below leans on
   schemas we already have or trivially extend — not a from-scratch model.
3. **Integrate, don't compete.** A built-in SIEM is a tar pit. A clean
   SIEM exporter ships in a week. Pick the latter.
4. **LLMs as analyst surfaces, not as a chatbot widget.** Specific,
   evaluated prompts wired into specific UI panels — never a generic
   "chat with your data" sidebar.
5. **Solo-developer scope.** If a phase needs a team, it gets cut or
   sliced thinner until one person can ship it and maintain it.

---

## Phase 1 · Enrichment & Detection-as-Code

**Target window: 2026-06 → 2026-07**  ·  **Status: 🟢 Closed** (10 of 10 items shipped — VirusTotal v3 + AbuseIPDB already in master since pre-Phase-1; EPSS, Shodan, inKev shipped 2026-06-05; urlscan.io + GreyNoise shipped 2026-06-08; Sigma ingester + MITRE tag mapping + YARA persistence + scan-sample upload shipped 2026-06-08; confirmed-phishing coverage via the OpenPhish + URLhaus + urlscan.io triad reframed 2026-06-09 — PhishTank dropped because registrations have been paused indefinitely upstream, and CVSS v4 moved to the non-goal list because v3 + EPSS + KEV already covers the decision data.)

The highest-leverage phase: every enricher we add makes existing
dashboard cards more decision-useful, with near-zero schema churn.

### IOC enrichment chain

Pluggable enricher pattern — runs on ingest *and* on-demand via API.

- 🟢 **urlscan.io — URL/domain reputation + screenshots**
  (shipped 2026-06-08: `enrichURLScan()` searches existing public scans
  via `/api/v1/search/?q=page.url:...` or `page.domain:...`, returns the
  latest verdict (malicious / categories / brands), page metadata, and
  screenshot URL. Free tier of 1000 searches/day with `URLSCAN_API_KEY`;
  works unauthenticated at lower volume. Added to the default source
  set for url + domain enrichment.)
- 🟢 **GreyNoise Community — internet-noise filter**
  (shipped 2026-06-08: `enrichGreyNoise()` hits the v3 Community endpoint,
  returns classification + noise/riot flags + scanner name. Drops benign
  scanners (Shodan, Censys, security researchers) from priority. Community
  endpoint works without `GREYNOISE_API_KEY` at 50 lookups/day; with a
  free key, 10k/day. Added to the default source set for ip enrichment.)
- 🟢 **AbuseIPDB — community-reported abusive IPs**
  (already in master pre-Phase-1: `enrichAbuseIPDB()` in
  `packages/core/src/enrichment.ts` hits `/api/v2/check` with a 90-day
  abuse-confidence lookup; falls back gracefully when no
  `ABUSEIPDB_API_KEY` is set. Registered in the enrichment dispatch
  map and the provider registry.)
- 🟢 **Shodan InternetDB — passive enrichment, no key required**
  (shipped 2026-06-05: `enrichShodan()` falls back to internetdb.shodan.io
  when no `SHODAN_API_KEY` is set; surfaces open ports, hostnames, and
  known CVEs per IP. Default enrichment sources now include `shodan`
  alongside `virustotal` + `geoip`.)
- 🟢 **VirusTotal v3 — multi-engine consensus**
  (already in master pre-Phase-1: `enrichVirusTotal()` uses the v3 API
  for IPs / domains / URLs / hashes, returns harmless/suspicious/malicious
  vendor counts and the top-rated tags. Default enrichment source
  alongside Shodan + GeoIP.)
- 🟢 **Confirmed-phishing coverage — OpenPhish + URLhaus + urlscan.io**
  (already in master: `apps/worker/src/feeds/openphish.ts` pulls the
  OpenPhish free feed at confidence 90 with no API key required;
  URLhaus ingest covers the malicious-URL side of phishing-adjacent
  infra; `enrichURLScan()` cross-checks domain + URL submissions
  against urlscan's verdict block (phishing categorisation lives in
  `page.task.method = 'manual'` + `page.brand`). PhishTank was the
  original fourth source but they paused new-user registrations
  indefinitely in 2024 and have given no reopening signal as of
  2026-06-09 — dropped from the roadmap rather than left pending.
  Reachability stays equivalent because OpenPhish + URLhaus already
  cover what PhishTank's free feed surfaced.)

### Vulnerability scoring upgrades

- 🟢 **EPSS (FIRST.org) — exploit-prediction score**
  (shipped 2026-06-05: daily worker downloads `epss-scores-current.csv.gz`,
  bulk-UPDATEs `vulnerabilities.epss_score` + `epss_percentile`. First
  backfill scored 6,503 of 7,095 vulns; 951 sit at EPSS ≥ 0.5. Surfaced
  on the vulns list table, CVE drawer, and CVE detail page. Transforms
  *"X critical CVEs"* into *"X critical with EPSS ≥ 0.7"*.)
- *(Removed 2026-06-09: CVSS v4 moved to the "what we won't build" list
  below. v3 + EPSS + KEV is the strict-superset decision data for
  prioritisation today, and v4 publishers haven't caught up
  meaningfully enough to repay the schema churn.)*
- 🟢 **Surface `inKev` boolean on every vuln panel**
  (shipped 2026-06-05: data was already in `vulnerabilities.is_exploited`;
  `/v1/landscape/overview` now returns `vulnerabilities.inKev` count, the
  Threat Command tile renders "N high · M crit · K KEV", and the vulns
  list already had a KEV flame column + KEV-only filter toggle.)

### Detection rules — Sigma & YARA

- 🟢 **Sigma rule ingester + library API**
  (shipped 2026-06-08: `packages/core/src/sigma.ts` parses upstream
  SigmaHQ YAML into our `detection_rules` table with `rule_type='sigma'`,
  preserving the full `detection:` block + `logsource` so downstream
  converters (Splunk, Elastic, OpenSearch) have something to transform.
  Single rules or `---`-separated bundles. `POST /v1/sigma/rules` takes
  raw YAML or JSON-wrapped; `POST /v1/sigma/import/url` pulls from a
  URL. Pre-existing MISP-Galaxy sigma ingest keeps populating
  metadata-only rows alongside.)
- 🟢 **Sigma `tags:` → MITRE ATT&CK technique mapping**
  (shipped 2026-06-08: `attack.tNNNN[.NNN]` tags lift to canonical
  `TNNNN[.NNN]` IDs in `meta.mitre_techniques`; `attack.<kebab-tactic>`
  tags lift into `meta.mitre_tactics`. Queryable via
  `GET /v1/sigma/by-technique/:techniqueId` using a JSONB containment
  predicate. Lower-case Sigma convention round-trips to upper-case
  MITRE form.)
- 🟢 **YARA rule storage + scan-uploaded-sample endpoint**
  (shipped 2026-06-08: in-memory YARA engine now persists user-added
  rules to `detection_rules` with `rule_type='yara'` and re-hydrates on
  startup so custom rules survive restart. Built-in rules stay
  code-only. `POST /v1/yara/scan-sample` accepts multipart/form-data
  or `application/octet-stream` up to 25 MiB; binary samples scan via
  latin1 decoding so hex patterns match raw bytes.)

---

## Phase 2 · STIX 2.1 first-class & Federation

**Target window: 2026-08 → 2026-09**  ·  **Status: 🟢 Closed** (5 of 5 items shipped — provenance/TLP + bundle import expansion + outbound TAXII push 2026-06-08 AM; STIX entity tables for campaign/course-of-action/infrastructure + relationship_type CHECK constraint + Neo4j auto-hydrate on relationship INSERT 2026-06-08 PM. `bundle.tar` packaging and hop-based TLP propagation deferred as small follow-ons; not blockers for federation.)

We speak TAXII but the internal model is still IOC-centric. STIX as
source of truth opens up federation between Rinjani instances and with
MISP / OpenCTI / vendor stacks.

- 🟢 **Full STIX 2.1 entity coverage** for the 10 Phase-2 SDO types:
  (shipped 2026-06-08: new `campaigns`, `courses_of_action`,
  `infrastructure` tables in migration 0046. The remaining seven were
  already covered before this phase started — `indicator` ↔ `iocs`,
  `vulnerability` ↔ `vulnerabilities`, `threat-actor` ↔ `threat_actors`,
  `malware` ↔ `malware`, `tool` ↔ `tools` (MITRE schema),
  `attack-pattern` ↔ `techniques` (the MITRE seed), `intrusion-set` is
  aliased to `threat_actors` because the relational model doesn't
  distinguish them. `note` and `opinion` remain skip-only by design —
  they're commentary, not entities, and the importer's
  `skippedTypes` counter surfaces them to the dashboard.)
- 🟢 **Typed relationships + Neo4j auto-hydration**
  (shipped 2026-06-08: `relationship_type` now constrained to the STIX 2.1
  §5.7 SRO common vocab + project-specific extensions via DB CHECK
  constraint (migration 0045) and a Zod enum on `POST /v1/relationships`.
  Both the user-facing route AND the STIX-bundle importer fire
  `autoHydrateRelationship()` on INSERT — a side-effect that MERGEs the
  matching Cypher edge in Neo4j. Mismatched labels, missing nodes, or
  driver failures are logged but never block the SQL write. Existing
  shortest-path endpoint at `findShortestPath(from, to, maxDepth)` now
  sees a fully-hydrated graph.)
- 🟡 **Bundle import/export** — JSON works both ways with full SDO
  coverage; `.tar` packaging follow-on. (shipped 2026-06-08: import
  expanded to handle `malware`, `campaign`, `course-of-action`,
  `infrastructure`, and `relationship` with full ref-resolution.
  `identity` + `marking-definition` counted but not persisted (they're
  bundle metadata); `note` + `opinion` skip-only.)
- 🟢 **TAXII 2.1 push client**
  (shipped 2026-06-08: new `taxii_remote_targets` table + REST CRUD at
  `/v1/taxii/remote-targets/*`, plus `POST /v1/taxii/remote-targets/:id/push`
  for one-shot pushes and `POST /v1/taxii/push-all` for the fan-out. Per-target
  filter mirrors `STIXExportOptions`, so each remote can subscribe to a
  different slice — e.g. "TLP:GREEN urlhaus + threatfox IOCs only, no
  threat-actors". Bearer token resolves from `config_api_keys.id` or
  the `TAXII_PUSH_API_KEY` env var. Last-push status persists on the
  target row.)
- 🟢 **Confidence + TLP marking propagation**
  (shipped 2026-06-08: `stixProvenance.ts` moved to `@rinjani/core/stixProvenance`
  and wired into the export pipeline. Every emitted `indicator`, `threat-actor`,
  and `vulnerability` now carries `created_by_ref`, `object_marking_refs`,
  `confidence` (0-100), and the custom `extension-definition--provenance`
  block with merge history + data-quality scoring. Per-source TLP defaults
  map known feeds to sensible markings (alienvault → WHITE,
  virustotal → GREEN, misp → AMBER); operator can override per-bundle
  via `STIXExportOptions.defaultTlp`. The bundle now also emits the
  referenced identity + marking-definition SDOs as required by STIX 2.1.
  Hop-based TLP propagation through the `relationships` graph is the
  follow-up that closes this fully.)

> **Differentiator we're leaning into**: graph-native attribution.
> *"Everything attributed to this intrusion set through any path
> ≤ 3 hops"* is a Cypher query for us; vendor stacks fake it with
> recursive SQL self-joins.

---

## Phase 3 · LLM analyst features

**Target window: 2026-10 → 2026-11**  ·  **Status: 🟢 Closed** (5 of 5 items shipped — embedding similarity backend (pre-Phase-3) + actor activity summarisation + NL→Cypher all shipped 2026-06-08; report ingestion shipped 2026-06-09 with text/PDF/URL inputs + persist + review/commit lifecycle; hypothesis tracking shipped 2026-06-09 with LLM-graded confidence + deterministic-fallback grader so the surface works without a provider key.)

Provider abstraction (Gemini / OpenRouter / Ollama) already exists. This
phase wires it into the analyst workflow, deliberately scoped to specific
surfaces rather than a generic chat widget.

- 🟡 **Report ingestion** — paste a PDF or URL; extract IOCs + TTPs +
  actors into STIX entities for review
  (scaffold shipped 2026-06-09: `POST /v1/reports/ingest-text` accepts
  operator-pasted text (up to 200 KB) and returns a structured draft
  combining (a) deterministic regex extraction for value-shaped IOCs —
  IPv4 / IPv6 / domains / URLs / MD5 / SHA-1 / SHA-256 / emails / CVEs,
  with defang refanging (`evil[.]com`, `hxxp://`, `[@]`) and file-
  extension filtering (`report.pdf` is not an IOC) — and (b) the
  existing `extractEntities()` LLM helper for fuzzy entities (threat-
  actor names, malware families, campaigns, MITRE techniques, target
  sectors, countries). LLM degrades gracefully: if no provider is
  reachable, the deterministic IOCs still surface and the response
  carries an `llmError` field so the operator knows what's missing.
  The extracted draft is read-only — operator decides what to import.
  PDF + URL input modalities added 2026-06-09 in PR #85:
  `POST /v1/reports/ingest-pdf` accepts multipart uploads up to 25 MB
  (text-only via `pdf-parse` — no OCR, so image-only scans surface
  `pageCount: N, textLength: 0`); `POST /v1/reports/ingest-url`
  fetches an http/https URL with a 15 s timeout + 5 MB body cap and
  runs a Cheerio-based readability shim (drops script/style/nav/
  footer/aside, prefers `<article>` over `<main>` over `<body>`, no
  jsdom). Both paths feed the same downstream IOC + LLM pipeline as
  text-paste and add a `sourceMeta` block to the response so operators
  know what came in.
  Review/commit flow added 2026-06-09 in PR #86: new
  `extracted_reports` table (migration 0049) persists every draft with
  full provenance (`source` + `source_kind` + `source_meta`),
  lifecycle state (`draft` | `committed` | `dismissed`), and audit
  attribution (`created_by` + `committed_by` + `commit_summary`).
  Routes: `GET /v1/reports` (filterable by status),
  `GET /v1/reports/:id`, `POST /v1/reports/:id/commit` upserts
  operator-approved IOCs into the canonical `iocs` table — idempotent
  against the unique-value constraint, doesn't downgrade
  severity/confidence on re-import. `POST /v1/reports/:id/dismiss`
  ends the lifecycle without import. Honest scope: CVE drafts are
  skipped at commit (they belong in `vulnerabilities`, not `iocs`);
  LLM entity commit (threat-actor / malware-family / campaign → STIX
  rows) is a separate follow-on that needs name disambiguation logic.)
- 🟢 **Actor activity auto-summarisation**
  (shipped 2026-06-08: `GET|POST /v1/threat-actors/:id/summary?days=30`
  reads the actor row + recent relationships, outgoing-edge distribution,
  top malware/tools, recent campaigns, and recent IOCs in a configurable
  lookback window. The activity block feeds a strict RAG prompt that
  explicitly forbids hallucinating IOCs / campaign names / malware that
  aren't in the data. Returns markdown plus a structured `activity` block
  so the UI can show "based on N IOCs + M campaigns". Provider
  override (`gemini` | `openrouter` | `ollama`) supported per call.)
- 🟢 **Embedding similarity** — *"have we seen this before"* loop
  (backend already in master pre-Phase-3: `POST /v1/search/vector` runs
  k-NN against OpenSearch's `knn_vector` index, `GET /v1/search/similar/:docId`
  returns the N most semantically-similar docs for any IOC / pulse / CVE.
  Embeddings come from `@xenova/transformers` locally (384-dim, no
  network) or any of the configured cloud providers. Batch reindex via
  `POST /v2/search/rebuild-with-vectors`. The dashboard-side "Similar
  IOCs" sidebar is the remaining work and lives in the dashboard repo.)
- 🟢 **Natural-language → Cypher**
  (shipped 2026-06-08: `POST /v1/graph/nl-query` takes an English
  question and returns the generated Cypher + Neo4j records. Three
  layers of safety: (1) the system prompt documents the schema and
  forbids writes, (2) `isReadOnlyCypher()` regex-blocks CREATE / MERGE
  / SET / DELETE / DETACH / REMOVE / DROP and dangerous CALL procedures
  even on word boundaries — DELETED_AT property names won't false-trigger,
  (3) `executeCypher()` opens the Neo4j session in READ access mode so
  the driver itself rejects writes. Defensive prose-stripping handles
  LLMs that ignore the "no fence, no prose" instruction. 26 unit tests
  cover the safety guard and extractor.)
- 🟢 **Hypothesis tracking** — *"I think Group A is using infrastructure
  X"* → LLM grades evidence as it accumulates from feeds
  (shipped 2026-06-09: two new tables in migration 0050 —
  `hypotheses` (id, title, claim, status `active`|`confirmed`|`refuted`,
  confidence_score 0..100, optional subject anchor, last-grading meta
  for audit) + `hypothesis_evidence` (FK to hypothesis, evidence_type
  ioc/relationship/sighting/actor/malware/campaign/report/freeform,
  optional entity_id, kind `supports`|`refutes`, weight 0..100,
  free-text note). Routes: `POST /v1/hypotheses` create,
  `GET /v1/hypotheses` list (filter by status/subjectType/subjectId),
  `GET /v1/hypotheses/:id` detail with evidence + support/refute
  stats, `PATCH /v1/hypotheses/:id` for lifecycle transitions,
  `POST /v1/hypotheses/:id/evidence` append (rejects on non-active
  status with NOT_ACTIVE), `POST /v1/hypotheses/:id/grade` runs the
  LLM grader. Grader prompt is deliberately narrow — supporting vs
  refuting buckets, sorted by weight, capped at 25 per side; strict
  guidance bands map confidence ranges to evidence shape; LLM is
  forbidden from inventing items not in the evidence list. Honest
  graceful degradation: when no LLM provider is reachable (or the
  caller passes `skipLlm: true`), the grader returns a deterministic
  weighted-average score with a transparent "(no LLM)" prefix in the
  reasoning — the surface keeps working in offline dev. LLM response
  parser tolerates stray prose and clamps confidence to the 0..100
  range. 30 unit tests cover schema validation rules (subject pair,
  freeform-needs-note), prompt builder ordering + caps, response
  parser edge cases, and the deterministic fallback math.)

> **Honest trade-off**: highest marketing value per hour invested IF
> prompts stay tight and evaluated. Will become a tar pit if we let it
> sprawl. Each surface ships with golden-output evals before merge.

---

## Phase 4 · Outbound integrations

**Target window: 2026-12 → 2027-02**  ·  **Status: 🟢 Closed** (6 of 6 items shipped — SIEM CEF/LEEF/ECS codecs + Fortinet/PAN/Cisco blocklist feeds + Teams/Discord/PagerDuty notification adapters + rule DSL + playbook condition DSL with step guards + sandbox triggers across ANY.RUN/Joe Sandbox/Hybrid Analysis with scheduled polling, all shipped 2026-06-08; ticketing fully closed 2026-06-09 with GitHub Issues + JIRA Cloud + GitHub webhook ingest; SIEM direct push closed 2026-06-09 with Splunk HEC + Elastic _bulk clients. Sentinel Log Analytics is a documented follow-up but not a phase blocker — Splunk + Elastic cover the vast majority of production SIEMs.)

Make the platform an active participant in the analyst's stack, not a
walled garden.

- 🟢 **Notification routing** — Slack, Email already shipped pre-Phase-4;
  Teams + Discord + PagerDuty + rule DSL shipped 2026-06-08.
  (Teams via MessageCard, Discord via embed, PagerDuty via Events API v2
  with auto-derived `dedup_key`. Test endpoints at
  `/notifications/test/{teams,discord,pagerduty}`. New rule DSL at
  `services/notificationChannels.ts` matches on `severityIn` / `typeIn` /
  `requireData` and routes to N channels per rule; `resolveRuleChannels()`
  dedupes overlapping rules. `/notifications/evaluate-rules` lets analysts
  dry-run a rule against a payload; `/notifications/dispatch` actually
  fires the matched channels.)
- 🟢 **SIEM exporters** — JSON/CSV/MISP/STIX/IDS-rules already shipped;
  CEF + LEEF + ECS NDJSON shipped 2026-06-08 via
  `POST /v1/export/{cef,leef,ecs}` (codecs in
  `@rinjani/core/siemFormatters`). Direct push closed 2026-06-09:
  `POST /v1/siem/push/splunk` ships ECS-shaped events to a Splunk HEC
  endpoint (`SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN`, optional
  `SPLUNK_HEC_INDEX` / `SPLUNK_HEC_SOURCETYPE`); `POST /v1/siem/push/elastic`
  ships the same data to an Elasticsearch / OpenSearch cluster's
  `_bulk` endpoint (`ELASTIC_URL` + either `ELASTIC_API_KEY` or
  `ELASTIC_USER`+`ELASTIC_PASSWORD`, optional `ELASTIC_INDEX`). Both
  clients fail closed without credentials, share the same filter
  schema as the export routes (with a stricter 5k batch cap vs 100k
  for downloads), and use the IOC id as the doc `_id` so re-runs
  upsert instead of duplicating. Sentinel Log Analytics API stays a
  follow-up but is not a blocker — the two clients above cover the
  vast majority of production SIEMs.
- 🟢 **SOAR-style playbooks DSL**
  (engine existed pre-Phase-4 with trigger event + flat conditions +
  ordered actions; shipped 2026-06-08 PM: condition DSL extended via
  `@rinjani/core/playbookDsl` with operator vocabulary
  `$and / $or / $not / $eq / $ne / $in / $nin / $gt / $gte / $lt / $lte /
  $exists / $regex` plus dotted-key nested traversal — e.g.
  `enrichment.score: { $gte: 80 }`. Per-step guards: each action can
  carry `if`, `continueOnError`, and `label`. Skipped steps record a
  `result.skipped=true` audit entry rather than counting as a failure.
  Legacy flat-shape conditions in existing rows keep working. Bug fix
  alongside: legacy matcher silently skipped conditions for missing
  fields — the new evaluator rejects (use `$exists: false` to assert
  absence explicitly).)
- 🟢 **Blocklist exports** — CSV, MISP feed, STIX, Fortinet, Palo Alto,
  Cisco firewall formats; cached, signed, served at stable subscribable
  URLs.
  (shipped 2026-06-08: Fortinet External Block List + Palo Alto External
  Dynamic List + Cisco threat-feed text formats via
  `GET /v1/feeds/blocklist/:vendor/:type` for ip/domain/url. Per-vendor
  validation rejects malformed entries before they reach the firewall.
  ETag + 5-min Cache-Control + `X-Rinjani-Signature: sha256=...` HMAC
  header backed by `BLOCKLIST_FEED_SECRET` env var. Falls back to a
  per-process random secret in dev. Public-readable by default; gate
  with `BLOCKLIST_FEED_REQUIRE_AUTH=true` if needed.)
- 🟢 **Sandbox triggers** — Joe Sandbox, ANY.RUN, Hybrid Analysis (kick
  off, store the report, link it to the originating IOC)
  (shipped 2026-06-08: new `sandbox_reports` table in migration 0047
  with FK to `iocs`. Three vendor clients live: ANY.RUN, Joe Sandbox
  (form-encoded auth), Hybrid Analysis (`api-key` header + UA). All
  three normalise into the same `{status, verdict, score, raw}` shape
  via per-vendor mappers. Umbrella service exposes
  `submitForAnalysis` + `refreshSandboxReport` + list/detail; routes at
  `POST /v1/sandbox/submit` + `GET /v1/sandbox/reports` + `:id/refresh`.
  New `sandbox_trigger` playbook action type so a "high-confidence IOC
  observed" playbook auto-detonates. Scheduled poller on its own
  `sandbox-polling` queue refreshes non-terminal reports every 5 min;
  per-row 1-day TTL caps API quota burn on dead submissions; per-batch
  parallelism capped at 8. File-upload submissions are the remaining
  follow-on.)
- 🟢 **Ticketing** — JIRA + GitHub Issues two-way sync for investigation
  tracking
  (fully shipped 2026-06-09: new `ticket_links` table in migration 0048
  joining `cases` ↔ external issues; unique on
  `(vendor, vendor_repo, vendor_issue_id)` so the same external issue
  can't be double-linked. GitHub Issues client (PR #72) covers create +
  fetch + comment via the v2022-11-28 REST API with PAT auth
  (`GITHUB_TICKETING_TOKEN`). JIRA Cloud client (PR #74) mirrors the
  same surface against REST API v3 with Basic `email:token` auth
  (`JIRA_BASE_URL` + `JIRA_EMAIL` + `JIRA_API_TOKEN`), ADF-wrapped
  descriptions + comments, and `statusCategory.key`-based status
  mapping that survives custom workflow names. Umbrella service result
  type normalised to a vendor-agnostic `issueId: string` so
  `vendor_issue_id` accepts both `"42"` and `"RIN-42"`. Inbound GitHub
  webhook ingest (PR #75) at `POST /v1/webhooks/github/issues` closes
  the bidirectional loop — HMAC-SHA256 verification via
  `GITHUB_WEBHOOK_SECRET`, narrow action gating
  (`closed`/`reopened`/`edited`), unknown links acknowledged so GitHub
  doesn't retry-storm. Without credentials every outbound call fails
  closed with a 502 + "not configured" message; the webhook route
  503s without its secret. Umbrella routes:
  `POST /v1/cases/:id/tickets`, `GET /v1/cases/:id/tickets`,
  `GET /v1/tickets`, `POST /v1/tickets/:id/refresh`,
  `POST /v1/tickets/:id/comment`. Honest note: JIRA path is
  code-complete + unit-tested but not live-tested against a real
  tenant — no JIRA test bed available; GitHub path will be live-
  validated against the cti-platform-api repo's own issues.)

---

## Phase 5 · Surface monitoring

**Target window: 2027-03 → 2027-05**  ·  **Status: 🟢 Closed** (5 of 5 items shipped — brand / typo-squat monitoring 2026-06-09 with dnstwist-style permutations + scheduled 6h DNS sweep; threat-actor TTP changelog 2026-06-09 with snapshot-based differ on the existing relationships table + daily 04:30 UTC scheduled run; HIBP breach catalog 2026-06-09 with free-tier `/breaches` sync only — paid `/breachedaccount` intentionally out of scope; dark-web Ahmia indexed search 2026-06-09 with Cheerio-based parser + daily 07:00 UTC scan; paste-site monitoring 2026-06-09 with GitHub Gist firehose matcher + 30-min scheduler. Telegram public channels, Pastebin's paid firehose, and CertStream realtime stream remain documented follow-ons but not phase blockers.)

Where we stop being a feed aggregator and start being a sensor network.
Ethics and scope matter here — each item is framed deliberately narrow.

- 🟢 **Brand / typo-squat monitoring** — CertStream + Levenshtein /
  DNS-twist; alerts on newly registered look-alikes of monitored domains
  (shipped 2026-06-09: two new tables in migration 0051 —
  `monitored_domains` (apex, label, owner, enabled, last_swept_at) +
  `brand_alerts` (FK to monitored_domains, permutation, algorithm,
  dns_state `active`|`mx_only`|`nx`|`error`, ip_addresses, composite
  score 0..100, lifecycle `new`|`triaging`|`escalated`|`benign`|
  `blocked`, first/last_seen). Pure dnstwist-style permutation
  generator in `@rinjani/core/domainPermutations` covers 9 algorithms
  — bitsquat / homoglyph / insertion / omission / substitution /
  transposition / vowel-swap / hyphenation / subdomain — plus
  Levenshtein for the scoring side. Scheduled 6h sweep walks every
  enabled apex, resolves each permutation via Node's system DNS
  (3 s per-permutation timeout, batches of 16, 2k cap per apex), and
  upserts on a `(monitored_domain_id, permutation)` unique. Score
  combines DNS state (+40 if active/mx_only), freshness (+20 if
  first-seen ≤ 7 days), TLD match (+20), and Levenshtein ≤ 2 (+20).
  Routes: full CRUD on `/v1/brand/domains`, ad-hoc `POST .../sweep`
  + sweep-all, `GET /v1/brand/alerts` triage queue ordered by score
  desc, `PATCH /v1/brand/alerts/:id` for analyst lifecycle. 28 unit
  tests cover the permutation generator, splitApex (co.uk-style
  TLDs), Levenshtein, scoring bands, and the Zod schemas. CertStream
  WebSocket integration (realtime cert-issuance signal — the freshest
  source for newly-registered typo-squats) and WHOIS-date lookups
  are documented follow-ons; the DNS sweep alone is a credible
  starting point.)
- 🟢 **Leaked credentials** — HIBP API integration scoped to monitored
  domains
  (shipped 2026-06-09: free-tier `/breaches` sync only — the paid
  `/breachedaccount` endpoint stays out of scope at $4/month per
  operator. New `data_breaches` table (migration 0053) mirrors the
  full HIBP catalog (~700 entries) with provenance + sync timestamps
  + raw payload stash. Sync service (`services/feedSync/hibpSync.ts`)
  hits the unauthenticated endpoint with a compliant `User-Agent`,
  upserts on `name` unique, captures the full upstream object in
  `raw_data` so any HIBP field we don't model is recoverable.
  Registered in the feed dispatch map as `'hibp'` so it inherits the
  standard `feed-sync` worker + UI + override surface. Scheduler:
  daily at 06:30 UTC, lands 30 min after the EPSS run. Routes:
  `GET /v1/data-breaches` (filter by domain / addedSince /
  breachSince / include-retired/-spam/-fabricated toggles — default
  hides all three to keep the analyst feed clean),
  `GET /v1/data-breaches/:name`, `POST /v1/data-breaches/sync`
  admin-only ad-hoc trigger. 14 unit tests cover the pure mapper
  (date parsing fallbacks, missing-Domain → null, malformed
  DataClasses element drop, boolean defaults, rawData passthrough
  for forensic recovery) and the Zod filter schema.)
- 🟢 **Paste-site monitoring** — public Telegram channels, GitHub Gist
  firehose, pastebin replacements (no scraping behind auth)
  (shipped 2026-06-09: scoped to GitHub Gist firehose for the first
  cut. Two new tables in migration 0055 — `paste_watchterms`
  (operator-curated terms, UNIQUE per term) + `paste_mentions`
  (source `github_gist`, author, filename, title, external_url,
  external_id, snippet, score 0..100, lifecycle
  `new`|`triaging`|`escalated`|`benign`|`blocked`, UNIQUE on
  `(watchterm_id, source, external_id)` so re-scans collapse to
  bumped last_seen_at). Pure matcher in `services/gistMonitor.ts`
  walks `/gists/public` (3 pages × 30/page per run), normalises each
  gist into `{id, owner, description, filenames, searchable}`, then
  scans every enabled watchterm against the lower-cased searchable
  text — emits one match row per (watchterm, gist) pair so a single
  gist hitting two watchterms creates two mentions. matchedFilename
  is surfaced when the term hits a filename specifically, which the
  UI uses to highlight the filename in the triage card. Auth: anon
  at 60 req/h or the existing `GITHUB_TICKETING_TOKEN` as Bearer for
  5000 req/h (no special scope required). Routes: full CRUD on
  `/v1/paste/watchterms` (+ admin DELETE), `POST /v1/paste/scan`
  ad-hoc, `GET /v1/paste/mentions` triage queue score desc,
  `PATCH /v1/paste/mentions/:id` analyst lifecycle. Scheduler runs
  every 30 min on the maintenance queue (gists churn fast — longer
  windows risk missing embeds before the author deletes them);
  `paste-gist-scan` dispatch added to `retentionWorker.ts`. 16 unit
  tests cover the normaliser (missing-field defaults, file-key
  fallback) and the matcher (case-insensitivity, filename-only hits,
  description-only hits, multi-watchterm-per-gist fan-out, empty-term
  skip, no-match empty array). Telegram public channels (bot token
  + per-channel subscription — different operational shape) and
  Pastebin (free `/scrape` deprecated, paid firehose out of scope)
  remain documented follow-ons.)
- 🟡 **Dark web** — Ahmia indexed search only. No direct `.onion`
  crawling on a single-VPS deployment — operationally messy, legally
  fraught in several jurisdictions, and outside solo-maintainer scope
  (scaffold shipped 2026-06-09: two new tables in migration 0054 —
  `dark_web_watchterms` (operator-curated search terms with kind +
  owner + enabled + last_searched_at) + `dark_web_mentions` (per-hit
  rows with source `ahmia`, title, onion_url, snippet, composite
  score 0..100, lifecycle `new`|`triaging`|`escalated`|`benign`|
  `blocked`, UNIQUE on `(watchterm_id, source, onion_url)` so re-runs
  collapse to a single row with bumped last_seen_at). Pure HTML
  parser in `services/ahmiaSearch.ts` uses Cheerio to walk
  `.result` elements, prefers `<cite>` for the onion URL, falls back
  to `<a href>` with Ahmia's `/search/redirect?redirect_url=...`
  unwrap, drops non-`.onion` results (donate links, ads). The
  platform queries clearnet ahmia.fi only — NEVER touches the Tor
  network, never fetches an onion URL. Scheduled daily at 07:00 UTC
  on the maintenance queue (30 min after HIBP); the
  `dark-web-ahmia-scan` dispatch case lives in `retentionWorker.ts`
  alongside the other maintenance jobs. Routes: full CRUD on
  `/v1/dark-web/watchterms`, ad-hoc `POST .../scan` + sweep-all,
  `GET /v1/dark-web/mentions` triage queue ordered by score desc,
  `PATCH /v1/dark-web/mentions/:id` analyst lifecycle. 12 unit tests
  cover the HTML parser. **2026-06-09 production validation:
  parser broken by upstream.** Ahmia moved search results to
  client-side rendering and discontinued the `/search/atom/` feed
  (returns 404). Our Cheerio selectors find zero `.result`
  elements in the live response — confirmed against the production
  droplet (clean 200 / 4.7 KB body containing only the landing
  page chrome). Three options on the table — (a) accept as a
  broken-by-upstream documented gap, (b) route through a Tor
  proxy and the real Ahmia onion address (conflicts with the
  "no Tor on a single VPS" non-goal), (c) replace with an
  alternative dark-web index (`darksearch.io` etc.). Tracked as
  the one open Phase 5 follow-on; the table + route layer is
  production-ready when an alternative source is wired up.)
- 🟢 **Threat-actor TTP changelog** — diff MITRE updates per group,
  alert when a tracked actor adopts a new technique
  (shipped 2026-06-09: two new tables in migration 0052 —
  `actor_ttp_state` (current known (actor, technique) tuples with
  observed_at + confirmed_at, UNIQUE per pair) + `actor_ttp_changes`
  (append-only log with change_type `added`|`removed`, detected_at,
  optional analyst note). Pure differ in `services/actorTtpDiffer.ts`
  reads the live (actor, technique) set from the existing
  `relationships` table (filter source_type=intrusion-set /
  target_type=attack-pattern / relationship_type=uses — the STIX
  2.1 vocabulary the MITRE feed sync writes; production live-test
  on 2026-06-09 found 49,927 rows under this filter and zero under
  our original `threat_actor`/`technique` Phase-1 internal names),
  compares against the snapshot, and emits one row per add/remove
  in a single transaction. First run = baseline (everything emits
  as added; the summary's `isBaselineRun:true` flag lets the UI dim
  that initial burst). Daily 04:30 UTC scheduled run on the
  maintenance queue, lands 30 min after the weekly MITRE sync (Sun
  04:00 UTC) so the first weekly diff has the freshest data; the
  same dispatch case in `retentionWorker.ts` handles the `mitre-ttp-diff`
  job type. Routes: `GET /v1/ttp-changes` global feed (filter by
  actor / technique / changeType / since), `GET /v1/actors/:id/ttp-changes`
  per-actor, `POST /v1/ttp-changes/run-diff` admin-only ad-hoc
  trigger. 14 unit tests cover the pure diff (no-change, add-only,
  remove-only, brand-new actor, deprecated actor, mixed both,
  per-actor isolation, empty input) and the Zod list filter.)

---

## Phase 6 · Platform & multi-tenancy

**Target window: 2027-06+**  ·  **Status: 🔵 Considering**

Deferred deliberately. We add this when a second tenant asks — not
before — otherwise it's over-engineering for a phantom requirement.

- 🔵 Hard tenant isolation: Postgres RLS + per-tenant OpenSearch
  index pattern + Neo4j label namespacing
- 🔵 Granular RBAC: per-source, per-TLP, per-actor visibility
- 🔵 SCIM provisioning + Keycloak federation (Keycloak hook already exists)
- 🔵 Audit-log streaming to S3 / ClickHouse
- 🔵 API-key scoping (admin / analyst / etc. exist — needs per-resource scope)
- 🔵 Per-tenant data-residency hooks (gateway routes by tenant claim)

---

## Cross-cutting (always-on, no phase)

Quality-of-life items that pay back every phase above. Worked on in the
margins, not gated behind a milestone.

- 🟢 **OpenTelemetry** through the BullMQ pipeline → expose trace IDs
  in the embedded Workbench
  (shipped 2026-06-11 → 2026-06-12 in PRs #96–#106. W3C `traceparent` is
  propagated across every queue boundary — feed-sync, ioc-enrichment,
  retention/maintenance, neo4j-sync, ai-analysis, notifications,
  stix-import-export, taxii-push, ticketing, etc. — via the producer-side
  `injectTraceContext()` helper and the worker-side `runJobWithSpan()`
  wrapper in `apps/api/src/queues/tracing.ts`. The v3-worker container
  was retired as part of this work; BullMQ scheduler is now the sole
  dispatcher. ~17 remaining `queue.add` producer sites are documented as
  follow-on hardening but don't break trace continuity — when a producer
  hasn't been migrated, the worker spans simply start fresh roots.)
- ⚪ **OpenSearch ILM** — hot/warm/cold policies; indices currently
  grow unbounded
- 🟢 **IOC decay** — `decayed_at` based on per-type staleness windows
  + read-path filtering across the dashboard surfaces
  (shipped 2026-06-12 → 2026-06-14 in PRs #105–#112. Migration 0058 adds
  `iocs.decayed_at timestamptz` + a BEFORE UPDATE trigger that clears
  it back to NULL when `last_seen` advances (so feed re-sightings
  un-decay transparently). Daily `confidenceDecay` BullMQ job stamps
  NOW() onto IOCs past their per-type staleness threshold (IPs 30 d,
  domains 60 d, hashes 180 d, etc. — `DECAY_RATES` in
  `apps/api/src/services/confidenceDecay.ts`). OpenSearch prune deletes
  decayed-IOC documents daily. Read-path filter on `/v1/iocs/cursor`,
  `/v1/stats/trending-tags`, `/v1/intelligence` actor-by-CVE +
  pulse-related-IOCs; default-hide-decayed with `?includeDecayed=true`
  override. Risk-score backfill (~268 k IOCs) ran 2026-06-14 → 2026-06-15
  on prod; first non-zero `totalUpdated` from the score-multiplied decay
  limb arrives the night after backfill completion.)
- ⚪ **TAXII contract tests** — cross-test against real PyTAXII2 and
  libtaxii clients; our endpoint should pass MISP & OpenCTI clients'
  real requests
- ⚪ **Performance budget** — `/v1/stats/overview` stays under 200 ms
  p95 as data grows; CI canary
- ⚪ **Feed-parser fuzzing** — every parser is an attack surface; AFL++
  on OTX, MISP, STIX parsers in CI
- 🟡 **Declarative feed connector engine** — replace hand-written
  TypeScript feed parsers with a pure, deterministic engine that runs
  declarative *manifests* (data, not code), authored in a UI or proposed
  by the LLM
  (in progress, A1–A4 of 7 shipped 2026-06-15 in PRs #113, #116, #117,
  #118. `@rinjani/feed-engine` is pure — no DB, no Redis, no network —
  and validates per-record output against per-entity zod schemas grounded
  in the canonical drizzle tables. Storage layer at `feed_manifest`
  (migration 0059, immutable rows + per-source single-active partial
  unique index); `/v1/connectors` CRUD with `created_by` audit trail.
  `feedSyncWorker` dispatch goes through `resolveFeedHandler()` which
  consults `FEED_ENGINE_ENABLED` + the manifest table — falls back to
  the legacy registry on any of: flag off, no active manifest, non-IOC
  entity, manifest fails engine zod, DB lookup throws. First migration
  target is ThreatFox — parity test asserts engine output matches the
  legacy handler on every detection-critical field; two improvements
  over legacy (per-hash type granularity, unknown-ioc-type rejection)
  are intentional and asserted in dedicated tests. Remaining: LLM
  draft-mapper at `/v1/connectors/suggest` reusing the existing provider
  abstraction with mandatory dry-run (A5), connector builder UI in
  `/admin/feeds` (A6), incremental per-feed migration each gated by its
  own parity test (A7).)

---

## What we won't build

Deliberate non-goals. Saying "no" early is how a solo project stays
shippable.

| Item | Why not |
|---|---|
| Built-in SIEM | Excellent ones exist; we integrate, not compete |
| Generic OSINT web crawler | A year of work to compete with `theHarvester`, `Maltego`, etc. — we narrow to cert streams + paste sites instead |
| Visual workflow editor on top of Workbench | Workbench's existing UI is good enough; the DSL approach in Phase 4 is leaner |
| Native mobile app | Dashboard is responsive; a separate React Native app is a tar pit for a solo dev |
| Built-in case management | JIRA / GitHub two-way sync covers 95% of this for 5% of the effort |
| Authoritative malware analysis | Sandbox *triggers* yes (Phase 4); building a sandbox no |
| CVSS v4 alongside v3 | v3 + EPSS + KEV is the strict-superset prioritisation signal today; v4 adoption among publishers remains sparse, so the schema + UI churn doesn't repay itself. Will reconsider when ≥ 20% of newly-published CVEs carry a v4 vector. |
| PhishTank integration | Registrations paused indefinitely upstream since 2024 with no reopening signal. OpenPhish + URLhaus + urlscan.io already cover what PhishTank's free feed surfaced. |

---

## Differentiators we're doubling down on

What we have that vendor stacks and most indie alternatives don't:

1. **Graph-native attribution** (Neo4j as a first-class store, not a
   bolt-on). Most indie CTI tools fake graph queries with SQL
   self-joins; we model the graph as the graph
2. **Embedded pipeline visibility** — Workbench fork at `/admin/workbench`
   lets analysts debug ingestion themselves, in the same tab they log
   in to. Rare even in vendor products
3. **LLM as analyst, not as chatbot** — narrow surfaces (summarisation,
   IOC extraction, similarity) with golden-output evals, not a generic
   "chat with your data" widget
4. **Vector search ready** — OpenSearch already configured with vector
   support; Phase 3 ships the wiring, but we're 80% there infrastructurally

---

## Contributing to the roadmap

This file is the source of truth, but the conversation happens elsewhere:

- **Feature ideas** → [GitHub Discussions](https://github.com/rinjanianalytics/cti-platform-api/discussions/categories/ideas)
- **Bugs & well-scoped work** → [GitHub Issues](https://github.com/rinjanianalytics/cti-platform-api/issues)
- **PRs against the roadmap** → especially welcome for Phase 1 enrichers;
  the pattern is well-defined, the scope is bounded, and one enricher
  per PR keeps the review surface tight

If you're working on something here, **drop a comment in the
corresponding issue** so we don't duplicate effort.

---

## Related repos

- [cti-platform-dashboard](https://github.com/rinjanianalytics/cti-platform-dashboard) — Next.js operator UI; its roadmap items (tri-state health, sparklines, etc.) live in that repo's issues
