/**
 * /v1/events — Semantic "what changed" stream for the dashboard's
 * attention rail.
 *
 * Distinct from `/v1/notifications` (which is the user-targeted inbox
 * showing per-user notification rows + read state, used by the topbar
 * bell's unread count). Events is platform-wide, **read-only**, and
 * surfaces meaningful threat-intelligence changes the analyst should
 * know about:
 *
 *   • KEV adds        — CVEs that joined CISA's Known Exploited
 *                       Vulnerabilities catalog in the last 7 days
 *   • CVE published   — recent high-CVSS (≥7) CVEs that aren't on KEV
 *                       (KEV-listed CVEs surface above; this avoids
 *                       double-rendering the same identifier)
 *   • Actor added     — new threat-actor rows created in the last 7d
 *                       (e.g. from STIX bundle ingest or analyst entry)
 *   • Pulse           — high-IOC-count pulses from the last 24h (>= 50
 *                       indicators is the "this is meaningful, not just
 *                       another tag" cutoff)
 *   • Sync            — feed-sync runs in the last 24h that failed or
 *                       completed partial — operational events the
 *                       analyst should react to before they cascade
 *
 * All five sources run in parallel and merge into a single timestamp-
 * sorted list. Cheaper than building a dedicated `platform_events`
 * table and a writer for every event kind — at the cost of some
 * query duplication on the read path. Fine while the event taxonomy
 * is small; revisit if it grows past ~10 kinds.
 *
 * Authenticated like the rest of /v1 (X-API-Key or Bearer); the
 * dashboard's fetch client attaches its session cookie automatically
 * so the attention rail populates as soon as the user is signed in.
 * Read-only — no mutating verbs are exposed here.
 */

import { Hono } from 'hono';
import { db, sql } from '@rinjani/db';

const router = new Hono();

export type EventKind = 'kev' | 'cve' | 'actor' | 'pulse' | 'sync'
    // Strategic-vertical events — the AI / On-chain / Telco surfaces.
    | 'ai-incident' | 'wallet' | 'telco';

export interface PlatformEvent {
    /** Stable per-event id so the client can dedupe / key React rows. */
    id: string;
    kind: EventKind;
    title: string;
    meta: string;
    /** ISO timestamp; the rail sorts and renders relTime from this. */
    timestamp: string;
    /** Optional deep-link target so clicking the row jumps to the entity. */
    href?: string;
}

/* ────────────────────────────────────────────────────────────────────────
   Row shapes — each query returns rows shaped to its source table; the
   `mapXyz` helpers below normalise them into `PlatformEvent`.
   ──────────────────────────────────────────────────────────────────── */

interface KevRow {
    cve_id: string;
    vendor_project: string | null;
    product: string | null;
    cvss_score: string | number | null;
    updated_at: Date | string;
}

interface CveRow {
    cve_id: string;
    vendor_project: string | null;
    product: string | null;
    cvss_score: string | number | null;
    description: string | null;
    published_date: Date | string;
}

interface ActorRow {
    id: string;
    name: string;
    sophistication: string | null;
    description: string | null;
    created_at: Date | string;
}

interface PulseRow {
    id: string;
    otx_id: string | null;
    name: string;
    author: string | null;
    indicator_count: number | null;
    otx_modified: Date | string;
}

interface SyncRow {
    id: string;
    entity_type: string;
    status: string;
    items_processed: unknown;  // JSONB number — coerce on read
    items_failed: unknown;
    error_message: string | null;
    completed_at: Date | string;
}

interface AiIncidentRow {
    incident_id: number;
    title: string;
    developers: string[] | null;
    incident_date: Date | string | null;
}

interface WalletRow {
    ref_id: string;
    address: string;
    chain: string;
    entity_label: string | null;
    risk_tags: string[] | null;
    created_at: Date | string;
}

interface FraudSchemeRow {
    ref_id: string;
    name: string;
    scheme_type: string;
    gsma_fs_categories: string[] | null;
    created_at: Date | string;
}

router.get('/events', async (c) => {
    const limitRaw = Number(c.req.query('limit') ?? 25);
    const limit = Math.min(Math.max(Math.floor(limitRaw) || 25, 1), 100);

    const [kevRows, cveRows, actorRows, pulseRows, syncRows, aiRows, walletRows, telcoRows] = await Promise.all([
        // 1. KEV adds — `is_exploited` flipped to true in the last 7d.
        //    Approximation: ORDER BY updated_at DESC for vulns where the
        //    flag is true. The flag flips during the daily kev-sync;
        //    `updated_at` is the row write timestamp, not the upstream
        //    catalog-added date, so this fires once per row update. Good
        //    enough for the rail's 2-hour window in practice.
        db.execute(sql`
            SELECT cve_id, vendor_project, product, cvss_score, updated_at
            FROM vulnerabilities
            WHERE is_exploited = true
              AND updated_at > now() - interval '7 days'
            ORDER BY updated_at DESC
            LIMIT 15
        `) as unknown as Promise<KevRow[]>,

        // 2. High-CVSS new CVEs (NOT on KEV — we don't want to render the
        //    same CVE twice as both a KEV add and a high-severity new
        //    CVE). 7-day window matches KEV.
        db.execute(sql`
            SELECT cve_id, vendor_project, product, cvss_score, description, published_date
            FROM vulnerabilities
            WHERE published_date > now() - interval '7 days'
              AND COALESCE(is_exploited, false) = false
              AND cvss_score IS NOT NULL
              AND cvss_score::numeric >= 7
            ORDER BY published_date DESC
            LIMIT 15
        `) as unknown as Promise<CveRow[]>,

        // 3. New actors tracked. `created_at` is the DB-row creation
        //    time — when our sync first saw this entity. For a brand-new
        //    feed source, this would surface every actor in that feed;
        //    in steady state it surfaces only genuinely-new STIX adds.
        db.execute(sql`
            SELECT id, name, sophistication, description, created_at
            FROM threat_actors
            WHERE created_at > now() - interval '7 days'
            ORDER BY created_at DESC
            LIMIT 15
        `) as unknown as Promise<ActorRow[]>,

        // 4. Significant pulses — high IOC count in last 24h. 50 IOCs is
        //    the rough cutoff between "a tag" and "a campaign-scale
        //    update". Tunable; not configurable today because no analyst
        //    has asked.
        db.execute(sql`
            SELECT id, otx_id, name, author, indicator_count, otx_modified
            FROM pulses
            WHERE otx_modified > now() - interval '24 hours'
              AND indicator_count > 50
            ORDER BY otx_modified DESC
            LIMIT 15
        `) as unknown as Promise<PulseRow[]>,

        // 5. Sync events — failures or partial completions in the last
        //    24h. We don't surface successes here (those are the routine
        //    "did the cron tick" rows); the analyst only needs to react
        //    to broken state.
        db.execute(sql`
            SELECT id, entity_type, status, items_processed, items_failed, error_message, completed_at
            FROM sync_logs
            WHERE status IN ('failed', 'partial')
              AND completed_at > now() - interval '24 hours'
            ORDER BY completed_at DESC
            LIMIT 10
        `) as unknown as Promise<SyncRow[]>,

        // 6. AI incidents — keyed on incident_date (the real-world event
        //    date), NOT created_at, so a one-time bulk feed ingest doesn't
        //    masquerade as "new". Surfaces genuinely-recent incidents.
        db.execute(sql`
            SELECT incident_id, title, developers, incident_date
            FROM ai_incidents
            WHERE incident_date > (now() - interval '30 days')::date
            ORDER BY incident_date DESC
            LIMIT 15
        `) as unknown as Promise<AiIncidentRow[]>,

        // 7. On-chain — newly SANCTIONED wallets only (the high-signal event).
        //    created_at is preserved across the daily OFAC re-upsert, so this
        //    fires only on genuinely-new SDN designations — not the bulk
        //    scam/protocol labels that would flood the rail.
        db.execute(sql`
            SELECT ref_id, address, chain, entity_label, risk_tags, created_at
            FROM wallets
            WHERE entity_type = 'sanctioned'
              AND created_at > now() - interval '7 days'
            ORDER BY created_at DESC
            LIMIT 15
        `) as unknown as Promise<WalletRow[]>,

        // 8. Telco — new fraud schemes added to the 5G taxonomy. Low volume
        //    (a curated model, not a live feed) so usually empty; surfaces
        //    when the telco entity model is extended.
        db.execute(sql`
            SELECT ref_id, name, scheme_type, gsma_fs_categories, created_at
            FROM fraud_schemes
            WHERE created_at > now() - interval '7 days'
            ORDER BY created_at DESC
            LIMIT 10
        `) as unknown as Promise<FraudSchemeRow[]>,
    ]);

    // Map each source's rows to events, KEEP THEM GROUPED. We deliberately
    // do NOT do a global timestamp sort + cap here because of the
    // "KEV-tsunami" problem: when the daily CISA-KEV sync flips
    // `is_exploited=true` on dozens of CVEs at once, every one of those
    // rows shares the sync run's `updated_at` timestamp. A naive
    // sort-by-timestamp puts the entire KEV batch at the top and the rail
    // becomes "10 KEV adds in a row", drowning out new actors, large
    // pulses, and failed syncs that an analyst actually wants to see in
    // the same glance.
    //
    // Instead: stratify per kind, then round-robin merge so each kind
    // gets a fair share of the visible window. Each kind is still
    // internally sorted DESC by its own timestamp; the round-robin
    // interleaves so the rail reads as a diverse "what changed across
    // cyber" feed rather than a single-source flood.
    const groups: PlatformEvent[][] = [
        kevRows.map(mapKev),
        cveRows.map(mapCve),
        actorRows.map(mapActor),
        pulseRows.map(mapPulse),
        syncRows.map(mapSync),
        aiRows.map(mapAiIncident),
        walletRows.map(mapWallet),
        telcoRows.map(mapTelco),
    ];
    const totalAcrossKinds = groups.reduce((n, g) => n + g.length, 0);

    // Round-robin merge with descending sort within each kind already
    // enforced by the SQL ORDER BY. Caps each kind at ceil(limit/kinds)
    // so no single source can hog more than its share even when its raw
    // count dwarfs the others.
    const perKindCap = Math.max(1, Math.ceil(limit / groups.length));
    const merged: PlatformEvent[] = [];
    const cursors = groups.map(() => 0);
    while (merged.length < limit) {
        let pickedAny = false;
        for (let i = 0; i < groups.length; i++) {
            const g = groups[i];
            const cursor = cursors[i];
            if (cursor >= perKindCap || cursor >= g.length) continue;
            merged.push(g[cursor]);
            cursors[i] = cursor + 1;
            pickedAny = true;
            if (merged.length >= limit) break;
        }
        if (!pickedAny) break; // every kind exhausted
    }

    return c.json({
        success: true,
        data: { events: merged, total: totalAcrossKinds },
    });
});

/* ────────────────────────────────────────────────────────────────────────
   Per-kind mapping helpers.
   ──────────────────────────────────────────────────────────────────── */

function mapKev(r: KevRow): PlatformEvent {
    const cvss = parseCvss(r.cvss_score);
    return {
        id: `kev:${r.cve_id}`,
        kind: 'kev',
        title: `${r.cve_id} added to CISA KEV`,
        meta: [
            r.vendor_project || r.product,
            cvss != null ? `CVSS ${cvss.toFixed(1)}` : null,
            'exploited in the wild',
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.updated_at),
        href: `/vulnerabilities/${encodeURIComponent(r.cve_id)}`,
    };
}

function mapCve(r: CveRow): PlatformEvent {
    const cvss = parseCvss(r.cvss_score);
    const inferred = inferVulnTitle(r.description);
    const productLabel = [r.vendor_project, r.product].filter(Boolean).join(' ') || 'product';
    return {
        id: `cve:${r.cve_id}`,
        kind: 'cve',
        title: inferred
            ? `${r.cve_id} — ${productLabel} ${inferred}`
            : `${r.cve_id} — ${productLabel}`,
        meta: [
            cvss != null ? `CVSS ${cvss.toFixed(1)}` : null,
            truncate(r.description, 80),
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.published_date),
        href: `/vulnerabilities/${encodeURIComponent(r.cve_id)}`,
    };
}

function mapActor(r: ActorRow): PlatformEvent {
    return {
        id: `actor:${r.id}`,
        kind: 'actor',
        title: `New actor tracked: ${r.name}`,
        meta: [
            r.sophistication,
            truncate(r.description, 70),
        ].filter(Boolean).join(' · ') || 'no description yet',
        timestamp: iso(r.created_at),
        href: `/actors/${encodeURIComponent(r.id)}`,
    };
}

function mapPulse(r: PulseRow): PlatformEvent {
    return {
        id: `pulse:${r.id}`,
        kind: 'pulse',
        title: truncate(`OTX pulse: ${r.name}`, 80) || `OTX pulse: ${r.name}`,
        meta: [
            r.author,
            r.indicator_count != null ? `${r.indicator_count.toLocaleString()} IOCs` : null,
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.otx_modified),
        href: `/feeds/${encodeURIComponent(r.otx_id || r.id)}`,
    };
}

function mapSync(r: SyncRow): PlatformEvent {
    const processed = Number(r.items_processed ?? 0);
    const failed = Number(r.items_failed ?? 0);
    const word = r.status === 'failed' ? 'failed' : 'partial';
    const feed = humaniseFeedName(r.entity_type);
    return {
        id: `sync:${r.id}`,
        kind: 'sync',
        title: `${feed} sync ${word}`,
        meta: r.error_message
            ? truncate(r.error_message, 90)!
            : [
                processed > 0 ? `${processed.toLocaleString()} processed` : null,
                failed > 0 ? `${failed.toLocaleString()} failed` : null,
            ].filter(Boolean).join(' · ') || 'see runbook',
        timestamp: iso(r.completed_at),
    };
}

function mapAiIncident(r: AiIncidentRow): PlatformEvent {
    const devs = Array.isArray(r.developers) ? r.developers.filter(Boolean) : [];
    return {
        id: `ai:${r.incident_id}`,
        kind: 'ai-incident',
        title: truncate(`AI incident: ${r.title}`, 80) ?? `AI incident #${r.incident_id}`,
        meta: devs.slice(0, 2).join(' · ') || 'incidentdatabase.ai',
        timestamp: r.incident_date ? iso(r.incident_date) : new Date().toISOString(),
        // Anchor-scroll to this incident in the "Latest" list (when present)
        // instead of the bare page.
        href: `/ai-incidents#ai-${encodeURIComponent(r.incident_id)}`,
    };
}

function mapWallet(r: WalletRow): PlatformEvent {
    const tags = Array.isArray(r.risk_tags) ? r.risk_tags.filter((t) => t && t !== 'sanctioned') : [];
    return {
        id: `wallet:${r.ref_id}`,
        kind: 'wallet',
        title: `Sanctioned wallet: ${r.entity_label || r.address}`,
        meta: [
            r.chain ? r.chain.toUpperCase() : null,
            tags.slice(0, 2).join(' · ') || 'OFAC SDN',
        ].filter(Boolean).join(' · '),
        timestamp: iso(r.created_at),
        // Deep-link to this wallet's attribution (the page auto-runs the lookup)
        // rather than dropping the user on the unfiltered on-chain page.
        href: `/onchain?address=${encodeURIComponent(r.address)}&chain=${encodeURIComponent(r.chain || 'ethereum')}`,
    };
}

function mapTelco(r: FraudSchemeRow): PlatformEvent {
    const cats = Array.isArray(r.gsma_fs_categories) ? r.gsma_fs_categories.filter(Boolean) : [];
    return {
        id: `telco:${r.ref_id}`,
        kind: 'telco',
        title: `Telco fraud scheme: ${r.name}`,
        meta: [r.scheme_type, cats.slice(0, 2).join(' · ')].filter(Boolean).join(' · ') || '5G signaling fraud',
        timestamp: iso(r.created_at),
        // Scroll to the fraud-schemes section rather than the page top.
        href: '/telco#schemes',
    };
}

/* ────────────────────────────────────────────────────────────────────────
   Utilities.
   ──────────────────────────────────────────────────────────────────── */

function iso(ts: Date | string): string {
    if (typeof ts === 'string') return ts;
    return ts.toISOString();
}

function parseCvss(raw: string | number | null): number | null {
    if (raw == null) return null;
    const n = typeof raw === 'number' ? raw : parseFloat(raw);
    return Number.isFinite(n) ? n : null;
}

function truncate(s: string | null, max: number): string | null {
    if (!s) return null;
    const trimmed = s.trim();
    return trimmed.length > max ? trimmed.slice(0, max - 1).trim() + '…' : trimmed;
}

/**
 * Best-effort guess at the vulnerability class from the CVE description.
 * Only used to enrich the headline ("IntelliJ RCE" > "IntelliJ"); falling
 * back to no suffix is fine.
 */
function inferVulnTitle(description: string | null): string | null {
    if (!description) return null;
    const d = description.toLowerCase();
    if (/\bremote code execution\b|\brce\b/.test(d)) return 'RCE';
    if (/\bcommand injection\b/.test(d))             return 'command injection';
    if (/\bsql injection\b/.test(d))                 return 'SQL injection';
    if (/\b(xss|cross-site scripting)\b/.test(d))    return 'XSS';
    if (/\bprivilege escalation\b/.test(d))          return 'privilege escalation';
    if (/\bbuffer overflow\b/.test(d))               return 'buffer overflow';
    if (/\bdeserialization\b/.test(d))               return 'deserialization vuln';
    if (/\bpath traversal\b/.test(d))                return 'path traversal';
    if (/\b(authentication bypass|auth bypass)\b/.test(d)) return 'auth bypass';
    if (/\binformation disclosure\b/.test(d))        return 'info disclosure';
    if (/\bdenial[- ]of[- ]service\b|\bdos\b/.test(d)) return 'DoS';
    return null;
}

function humaniseFeedName(entityType: string): string {
    // sync_logs.entity_type uses snake_case ("alienvault_pulses",
    // "cisa_kev"). Convert to a readable label for the rail.
    return entityType
        .split(/[_-]/)
        .map(p => p.charAt(0).toUpperCase() + p.slice(1))
        .join(' ');
}

export default router;
