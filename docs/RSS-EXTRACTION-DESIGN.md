# RSS + extraction ingestor — design

Fills the freshness gap identified in `FEED-CADENCE-AUDIT.md`: indicator feeds
are healthy, but the **attribution / narrative-TTP layer is static** (the TTP
changelog is ~11d–months stale because it derives from MITRE's biannual
catalogue). This ingestor brings **fresh, report-derived "actor X used technique
T# now"** into the same `actor_ttp_*` model, which makes the *Latest TTP
changelog* live and gives the ATT&CK coverage window a real time basis.

**Design principle: assemble, don't rebuild.** Every major piece already exists:

| Need | Reuse | File |
|---|---|---|
| RSS/Atom fetch · parse · filter · upsert | `telco-news.ts` (the template) | `apps/worker/src/feeds/telco-news.ts` |
| Structured extraction `{threatActors, techniques, …}` | `extractEntities()` + `callLLM()` cascade (gemini→openrouter→ollama) | `apps/api/src/services/aiMiddleware/helpers.ts:48`, `callLLM.ts` |
| Write target (fresh TTPs) | `actor_ttp_changes` + `actor_ttp_state` diff model, `note` for provenance | `packages/db/src/schema/actorTtpChangelog.ts` |
| Gazetteer (name/alias/T-code → STIX id) | `threat_actors` (name, aliases, realStixId), `techniques` (mitreId, realStixId) | `schema/threats.ts`, `schema/mitre.ts` |
| Job lifecycle + freshness tracking | `beginFeedSyncRun`/`completeFeedSyncRun`, `feed_sync_runs`, `JOB_REGISTRY`, `feedRegistry` | `queues/workers/feedSyncWorker.ts`, `queues/scheduler.ts` |
| Staging / HITL audit trail | `extracted_reports` (entities jsonb, draft→commit) | `schema/extractedReports.ts` |

## Sources (free, no paywall, ATT&CK-citing)

Curated, env-overridable list (`INTEL_NEWS_FEEDS`, `key|url` pairs, like
`TELCO_NEWS_FEEDS`). Lead with sources that cite technique IDs verbatim:

- **The DFIR Report** — full intrusions, ATT&CK-mapped (often a technique table). Highest TTP density.
- **CISA advisories (AA-series)** — timely, structured, ATT&CK-mapped. RSS/JSON.
- **Vendor CTI blogs (RSS):** Talos, Unit 42, Microsoft MSTIC, Securelist, ESET, SentinelOne, Volexity, Red Canary, Huntress.
- Already-paid-for and underused: **OTX pulses** already carry `pulses.attackIds` — fold them into the same extraction/diff path (no new fetch).

Out of scope here (separate track): Mastodon/Bluesky/Reddit/Telegram (the audit's social options) — RSS first, it's the highest signal-to-effort.

## Flow

```
hourly job (intelNewsSync)
  └─ for each feed: fetch (UA + conditional GET) → parse (fast-xml-parser)
       → upsert raw item (intel_reports, unique on url)            [Phase 1]
       → extract entities for new/changed items:                  [Phase 2/3]
            Tier 1 (no LLM): regex T-codes  /T\d{4}(\.\d{3})?/
                             + actor/alias match vs threat_actors gazetteer
            Tier 2 (LLM): extractEntities(text) for prose-described TTPs
       → resolve: mitreId→techniques.realStixId, name/alias→threat_actors.realStixId
       → for each (actor × technique) co-occurring in the item:
            if pair NOT in actor_ttp_state  → INSERT actor_ttp_changes
                 { changeType:'added', detectedAt: pubDate ?? now,
                   note: {source, url, method, confidence} }
              and UPSERT actor_ttp_state (observedAt = now)        ← fresh dedup baseline
  └─ completeFeedSyncRun(runId, …)   → shows in /v1/monitoring/feeds
```

The **`actor_ttp_state` dedup baseline** is the crux: it's the same model
`mitreTtpDiff` uses, so a report re-mentioning a known pairing is a no-op, and a
*genuinely new* attribution yields exactly one fresh changelog row with a real
`detected_at`. RSS becomes a second, *fast* writer into the existing diff model.

## Extraction tiers (precision first)

1. **Tier 1 — deterministic, no LLM, high precision.** Regex `T####(.###)?`
   for techniques cited verbatim (DFIR/CISA do this constantly) + gazetteer
   match for actors/aliases. Co-occurrence in one article ⇒ "actor uses
   technique". Cheap, runs always, no env key.
2. **Tier 2 — LLM recall.** `extractEntities()` for techniques described in
   prose ("they used PowerShell to…") and actor/malware names not in the
   gazetteer. Gated by `GEMINI_API_KEY`/`OPENROUTER_API_KEY`; **degrades
   gracefully to Tier-1-only** when no key.

## Confidence + provenance + HITL (noise control)

Narrative extraction is noisier than structured feeds — so:

- Every `actor_ttp_changes` row carries provenance in `note`:
  `{ "source":"dfir", "url":"…", "method":"regex|llm", "confidence":0.0–1.0 }`.
  Nothing is unattributable.
- **Confidence gate:** explicit verbatim T-code + gazetteer actor (Tier 1) →
  high → **auto-write**. LLM-only or fuzzy actor → **stage in
  `extracted_reports` (draft)** for one-click review rather than auto-polluting
  the changelog. Reuses the existing draft→commit machinery.
- Unknown actor (not in gazetteer, not aliased) → skip the pair (or stage as a
  candidate); never invent a threat_actor from a blog mention automatically.

## Cadence & politeness

- New job **`intelNewsSync`**, default `0 * * * *` (hourly — articles are
  time-sensitive; RSS is cheap). Conditional GET (ETag/Last-Modified) per feed,
  per-run item cap, UA header (mirror telconews).
- Registered in `JOB_REGISTRY` + `feedRegistry` exactly like `telconews`, so it
  appears in `/v1/monitoring/feeds` and the freshness chip.

## Schema

One small new table (raw narrative store; generalizes `telco_advisories`):

```
intel_reports
  id, source (feed key), external_id/url (unique), title, summary, body?,
  published_at, tags[], entities jsonb (extraction result),
  extraction_status ('pending'|'extracted'|'staged'|'committed'|'error'),
  llm_provider?, created_at, updated_at
```

Writes to existing `actor_ttp_changes` / `actor_ttp_state` (unchanged). No
change to `techniques`/`threat_actors` (read-only gazetteer). `telco_advisories`
can later fold into `intel_reports`, not required now.

## Phased plan

- **Phase 1 — Broad collection.** Generalize `telco-news.ts` → `intel-news.ts`
  over the curated source list; store raw items in `intel_reports`; register the
  job. *Outcome:* fresh narrative volume visible in monitoring; no TTP writes
  yet. Low risk, proves source coverage.
- **Phase 2 — Deterministic TTPs (the win).** Tier-1 regex+gazetteer →
  `actor_ttp_changes` via the state-diff dedup. *Outcome:* the *Latest TTP
  changelog* goes live (freshness chip flips to hours), no LLM dependency.
- **Phase 3 — LLM recall + confidence/HITL.** `extractEntities()` Tier 2;
  confidence gating; low-confidence staged in `extracted_reports` for review.
- **Phase 4 — Surface + window.** Confirm the changelog + ATT&CK coverage reflect
  fresh data; **re-base the ATT&CK coverage time-window on
  `actor_ttp_changes.detected_at`** (closes the loop from cti-platform-api#186 /
  v2-dashboard#5, where the window was meaningless against the static MITRE
  basis); add per-row source attribution in the UI.

## Risks / tradeoffs

| Risk | Mitigation |
|---|---|
| False attributions from prose | co-occurrence + confidence gate + HITL for low-confidence; provenance on every row |
| Actor name ambiguity / aliases | gazetteer match on `threat_actors.aliases`; unknown → skip/stage, never auto-create |
| Techniques only in prose (no T-code) | Tier-2 LLM; accept lower recall when no LLM key |
| RSS politeness / rate | conditional GET, per-run caps, hourly cadence |
| LLM cost/availability | Phase 2 is LLM-free and already useful; Tier 2 degrades gracefully |
| Duplicate/echoed reporting | `actor_ttp_state` dedup ⇒ one change per genuinely-new pairing |

## Definition of done (per phase)

P1: `intelNewsSync` healthy in `/v1/monitoring/feeds`, `intel_reports` filling.
P2: new `actor_ttp_changes` rows with `detected_at` within hours of publication,
each traceable to a source URL; dashboard freshness chip reads "updated <Nh".
P3: LLM-extracted candidates appear staged; reviewed ones commit.
P4: ATT&CK coverage window reacts meaningfully to 7d/30d again.
