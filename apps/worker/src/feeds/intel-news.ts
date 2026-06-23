/**
 * Intel News — broad threat-intel narrative ingestion (RSS).
 *
 * Phase 1 of RSS + extraction (docs/RSS-EXTRACTION-DESIGN.md): COLLECTION ONLY.
 * Generalises telco-news.ts over a curated set of free, ATT&CK-citing CTI
 * sources (The DFIR Report, CISA advisories, vendor blogs). No keyword filter —
 * the source list is the curation. Sink: intel_reports (upsert on the URL).
 *
 * Phase 2 reads these rows and extracts actor → technique TTPs into
 * actor_ttp_changes; that's why nothing here filters or discards.
 *
 * Operational note (from telco-news): some feeds are Cloudflare/Akamai-fronted
 * and may 403 from datacenter IPs (the prod droplet). Per-feed failures are
 * logged and skipped, never fatal; tune the live set via INTEL_NEWS_FEEDS
 * (comma-separated "key|url" pairs).
 */

import { XMLParser } from 'fast-xml-parser';
import { db } from '@rinjani/db';
import { intelReports } from '@rinjani/db/schema';
import type { NewIntelReport } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';
import { runIntelTtpExtraction } from './intel-ttp';

const log = createLogger('IntelNews');

const UA = process.env.INTEL_NEWS_UA
    ?? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// Curated CTI sources — free RSS/Atom, lead with the ones that cite ATT&CK
// technique IDs verbatim (DFIR Report, CISA AA) so Phase 2 extraction is dense.
const DEFAULT_FEEDS: Array<{ key: string; url: string }> = [
    { key: 'dfir',         url: 'https://thedfirreport.com/feed/' },
    { key: 'cisa',         url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
    { key: 'talos',        url: 'https://blog.talosintelligence.com/rss/' },
    { key: 'unit42',       url: 'https://unit42.paloaltonetworks.com/feed/' },
    { key: 'mssecurity',   url: 'https://www.microsoft.com/en-us/security/blog/feed/' },
    { key: 'securelist',   url: 'https://securelist.com/feed/' },
    { key: 'redcanary',    url: 'https://redcanary.com/feed/' },
    { key: 'thehackernews',url: 'https://feeds.feedburner.com/TheHackersNews' },
];

function feeds(): Array<{ key: string; url: string }> {
    const env = process.env.INTEL_NEWS_FEEDS;
    if (!env) return DEFAULT_FEEDS;
    return env.split(',').map((pair) => {
        const [key, url] = pair.split('|');
        return { key: (key ?? '').trim(), url: (url ?? '').trim() };
    }).filter((f) => f.key && f.url);
}

interface RssItem { title?: string; link?: unknown; description?: string; summary?: string; content?: string; 'content:encoded'?: unknown; pubDate?: string; published?: string; updated?: string }

/** RSS link is a string; Atom link is an object (or array) with @_href. Normalise. */
function linkOf(raw: unknown): string {
    if (typeof raw === 'string') return raw.trim();
    if (Array.isArray(raw)) {
        // Atom often has multiple <link> — prefer rel="alternate" / no rel.
        const alt = raw.find((l) => l && typeof l === 'object' && (!('@_rel' in l) || (l as Record<string, unknown>)['@_rel'] === 'alternate'));
        return linkOf(alt ?? raw[0]);
    }
    if (raw && typeof raw === 'object' && '@_href' in raw) return String((raw as Record<string, unknown>)['@_href'] ?? '').trim();
    return '';
}

// We parse with processEntities:false (avoids fast-xml-parser's entity-expansion
// DoS guard tripping on CISA's all.xml), so decode the handful of named/numeric
// entities ourselves.
function decodeEntities(s: string): string {
    return s
        .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"').replace(/&#0?39;|&#x27;/gi, "'").replace(/&nbsp;/g, ' ')
        .replace(/&#(\d+);/g, (_m, n) => { try { return String.fromCodePoint(Number(n)); } catch { return ' '; } })
        .replace(/&#x([0-9a-f]+);/gi, (_m, h) => { try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ' '; } });
}

function stripHtml(s: string): string {
    return decodeEntities(s.replace(/<[^>]*>/g, ' '))
        // Strip NUL + control bytes — Postgres text columns reject them
        // ("invalid byte sequence"/"unterminated"), which fails the whole insert.
        // eslint-disable-next-line no-control-regex
        .replace(/[\u0000-\u001f\u007f]/g, ' ')
        .replace(/\s+/g, ' ').trim();
}

function textOf(v: unknown): string {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object' && '#text' in v) return String((v as Record<string, unknown>)['#text'] ?? '');
    return '';
}

async function fetchFeed(url: string): Promise<RssItem[]> {
    const res = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml' } });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    const xml = await res.text();
    // processEntities:false — don't expand XML entities (security + sidesteps the
    // "Entity expansion limit exceeded" abort on CISA's feed). decodeEntities()
    // handles the &amp;/&#NN; we care about in titles/summaries.
    const parsed = new XMLParser({ ignoreAttributes: false, trimValues: true, processEntities: false }).parse(xml);
    const channel = parsed?.rss?.channel ?? parsed?.feed ?? {};
    const items = channel.item ?? channel.entry ?? [];
    return Array.isArray(items) ? items : [items];
}

export interface IntelNewsResult { processed: number; failed: number; errors: string[] }

export async function syncIntelNews(): Promise<IntelNewsResult> {
    const result: IntelNewsResult = { processed: 0, failed: 0, errors: [] };
    const rows: NewIntelReport[] = [];

    for (const feed of feeds()) {
        let items: RssItem[];
        try {
            items = await fetchFeed(feed.url);
        } catch (err) {
            result.errors.push(`${feed.key}: ${(err as Error).message}`);
            result.failed++;
            continue;
        }
        for (const it of items) {
            const title = stripHtml(textOf(it.title)).trim();
            const link = linkOf(it.link);
            if (!title || !link) continue;
            // Prefer the full post body (WordPress <content:encoded>) over the
            // RSS intro so Phase 3 LLM extraction sees the article, not just the
            // teaser. Bounded to 6000 chars (extractEntities' input window).
            const raw = textOf(it['content:encoded']) || textOf(it.content) || textOf(it.description) || textOf(it.summary);
            const summary = stripHtml(raw).slice(0, 6000);
            const dateStr = it.pubDate || it.published || it.updated;
            const published = dateStr ? new Date(dateStr) : null;

            rows.push({
                source: feed.key,
                externalId: link,
                title,
                url: link,
                summary: summary || null,
                tags: ['intel', 'news', feed.key],
                publishedAt: published && !Number.isNaN(published.getTime()) ? published : null,
            });
        }
    }

    log.info('Intel news collected', { items: rows.length });

    for (const row of rows) {
        try {
            await db.insert(intelReports).values(row).onConflictDoUpdate({
                target: intelReports.externalId,
                set: { title: row.title, summary: row.summary, tags: row.tags, publishedAt: row.publishedAt, updatedAt: new Date() },
            });
            result.processed++;
        } catch (err) {
            result.failed++;
            if (result.errors.length < 8) result.errors.push(`upsert ${row.url}: ${(err as Error).message}`);
        }
    }

    // Phase 2 — pull actor→technique TTPs out of the freshly-collected (and any
    // backlog) pending reports into actor_ttp_changes. Non-fatal: a collection
    // run still succeeds even if extraction hiccups.
    try {
        const ttp = await runIntelTtpExtraction();
        log.info('TTP extraction', ttp);
    } catch (err) {
        result.errors.push(`ttp-extract: ${(err as Error).message}`);
    }

    log.info('Intel news sync done', { processed: result.processed, failed: result.failed });
    return result;
}

// Standalone runner — `tsx apps/worker/src/feeds/intel-news.ts`.
export async function runIntelNewsSync(): Promise<void> {
    try { await syncIntelNews(); } catch (err) { log.error('Sync failed', err as Error); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runIntelNewsSync().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
}
