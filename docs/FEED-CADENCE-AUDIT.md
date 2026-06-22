# Feed cadence audit — 2026-06-22

Grounding for the **RSS + extraction** data-freshness work. Reconciles each
scheduled job's *configured cadence* (from `apps/api/src/queues/scheduler.ts`)
against its *actual freshness* (live `/v1/monitoring/feeds` + per-source data
timestamps, measured 2026-06-22).

## TL;DR

- **The indicator/vuln plumbing is healthy and fresh.** 15 of 18 feeds last
  synced < 12h ago; the high-velocity ones (CVE.org, OTX, abuse.ch, OpenPhish)
  are < 1.5h. There is **no broad "everything is behind" problem.**
- **The staleness is concentrated in the attribution / narrative-TTP layer** —
  the part that turns raw indicators into *who is doing what, now*:
  - `actor_ttp_changes` (the "Latest TTP changelog") newest row is
    **2026-06-10 (~11.6 days old)**. Root cause is **upstream staleness, not
    rate-limit or failure**: it diffs the MITRE ATT&CK relationships table, and
    MITRE only refreshes attribution ~biannually. Running the diff daily can't
    manufacture changes that the upstream doesn't publish.
  - The only live narrative source is `telconews` (healthy, 5.3h) — but it's
    narrow: telecom-keyword-filtered, two RSS feeds. It **proves the
    RSS→parse→upsert pattern already works in this stack.**
- **RSS + extraction targets exactly this gap** and should *not* touch the
  (healthy) indicator feeds.
- **Three incidental issues surfaced** (independent of RSS) — one is a real bug.

## Freshness matrix (measured 2026-06-22)

| Feed | Cadence | Last sync | Items (last run) | Verdict | Cause / note |
|---|---|---|---|---|---|
| cveorg | */15m | 0.1h | 16 | ✅ fresh | near-real-time CNA disclosures |
| otx | */15m | 0.1h | **0** | ⚠️ 0 new | subscribed-pulses quiet — verify key/subscription |
| cisa | hourly | 0.3h | 0 | ✅ | 0 new = KEV unchanged (daily upstream) |
| threatfox | 6h | 1.2h | 452 | ✅ | abuse.ch, near-real-time |
| urlhaus | 6h | 1.1h | 889 | ✅ | |
| malwarebazaar | 6h | 0.6h | 21 | ✅ | |
| abusessl | 6h | **20.5d** | 0 | ❌ stale | disabled/stuck override — decommission or fix |
| openphish | 4h | 1.3h | 300 | ✅ | |
| nvd | daily | 11.3h | 2000 | ✅ | capped 3 pages/run (rate-limited by design) |
| epss | daily | 7.2h | 15450 | ✅ | |
| hibp | daily | 6.8h | 1011 | ✅ | |
| ofac | daily | 10.3h | 200 | ❌ **failing** | `Batch insert failed: insert into "iocs"…` — only 200 rows, ingest error |
| scamsniffer | daily | 9.8h | 2530 | ✅ | |
| defillama | weekly | 9.3h | 2893 | ✅ | |
| aiid | daily | 0.3h | 1537 | ✅ | AI Incident DB |
| mispgalaxy | daily | 8.3h | 0 | ✅ | 0 new = actor enrichment static upstream |
| mitre | weekly | 1.4d | 6697 | ✅ runs | **but upstream ~biannual** → see TTP below |
| telconews | 8am/8pm | 5.3h | 100 | ✅ | narrow (telecom-only, 2 RSS) |
| **actor_ttp_changes** (derived by `mitreTtpDiff`) | daily diff | **11.6d** | — | ❌ stale | MITRE attribution is static knowledge, not a time-series |

Source volume (sanity): alienvault 242k · urlhaus 11.4k · openphish 9.8k ·
threatfox 9.1k · malwarebazaar 5.4k · scamsniffer 2.5k · otx 1.7k · ofac 200.

## The actual gap → what RSS + extraction must fill

The freshness deficit is **narrative attribution**, not indicators:

1. **Live TTPs.** Fresh "actor X used technique T1059 in campaign Y" comes from
   *reporting* (DFIR Report, CISA AA, vendor blogs), not from the MITRE catalog.
   Extract ATT&CK technique IDs + actor names from RSS items → write to
   `actor_ttp_changes` with a real `detected_at`. This makes the TTP changelog
   live **and** finally gives the ATT&CK coverage window a meaningful basis
   (the basis problem flagged in cti-platform-api#186 / v2-dashboard#5).
2. **Broaden the one working narrative feed.** `telconews` already does
   RSS→regex-filter→upsert into `telco_advisories`. Generalize it: a broader
   source set (CISA advisories, The DFIR Report, Talos/Unit42/MSTIC/Securelist,
   etc.) and an extraction step (technique IDs are often cited verbatim;
   actor/malware names via the LLM or a gazetteer).

Reuse, don't rebuild: `feed_sync_runs` already tracks per-feed last-sync;
`telconews` is the working template; the LLM agent + `actor_ttp_*` tables exist.

## Incidental issues (independent of RSS — fix separately)

1. **`ofac` batch insert is failing** — `Batch insert failed: Failed query:
   insert into "iocs"…`, only 200 rows ingested. Real ingestion bug; worth a
   targeted fix (likely a constraint/column mismatch on the OFAC→iocs batch).
2. **`abusessl` 20.5d / 0 items** — disabled-by-override or stuck. Decide:
   re-enable + fix, or formally decommission so it stops showing as a feed.
3. **`otx` last run ingested 0** despite 242k historical — likely just a quiet
   subscription window, but worth confirming the `ALIENVAULT_API_KEY` and that
   subscribed pulses are still flowing (OTX is a prime *fresh* narrative source
   we already pay nothing for).

## Cadence sanity notes

- `mitreTtpDiff` (daily 04:30) diffs a table `mitreSync` only refreshes weekly
  (Sun 04:00) → 6 of 7 daily runs are guaranteed no-ops. Harmless but wasteful;
  could gate on a fresh MITRE sync.
- The IOC feed cadences are well-tuned; nothing there needs changing for
  freshness.
