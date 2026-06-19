/**
 * Telco News — Tier-2 telco intel.
 *
 * No free telecom-specific threat feed exists (GSMA T-ISAC is membership-only).
 * So we ingest general security-news RSS and keep only items matching telecom
 * terms — giving the Telco vertical LIVE external reporting (campaigns, breaches,
 * Salt-Typhoon-class activity) on top of the Tier-1 pulse/CVE filter.
 *
 * Sources are free RSS (browser UA required by some CDNs). Sink: telco_advisories
 * (upsert on the article URL). `telcoIntel()` unions this in as kind 'advisory'.
 */

import { XMLParser } from 'fast-xml-parser';
import { db } from '@rinjani/db';
import { telcoAdvisories } from '@rinjani/db/schema';
import type { NewTelcoAdvisory } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('TelcoNews');

const UA = process.env.TELCO_NEWS_UA
    ?? 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// Free, reliable security-news RSS (override via TELCO_NEWS_FEEDS, comma-sep
// "key|url" pairs). The Hacker News + BleepingComputer both serve RSS 2.0.
const DEFAULT_FEEDS: Array<{ key: string; url: string }> = [
    { key: 'thehackernews', url: 'https://feeds.feedburner.com/TheHackersNews' },
    { key: 'bleepingcomputer', url: 'https://www.bleepingcomputer.com/feed/' },
];

function feeds(): Array<{ key: string; url: string }> {
    const env = process.env.TELCO_NEWS_FEEDS;
    if (!env) return DEFAULT_FEEDS;
    return env.split(',').map((pair) => {
        const [key, url] = pair.split('|');
        return { key: (key ?? '').trim(), url: (url ?? '').trim() };
    }).filter((f) => f.key && f.url);
}

// Telecom relevance — specific terms only (word-bounded short tokens), so a
// general security headline only surfaces when it's genuinely telecom.
const TELCO_RE = new RegExp(
    [
        'telecom', 'telco', 'telecommunications', '\\b5g\\b', '\\bss7\\b', 'diameter protocol',
        '\\bgtp\\b', 'signal+ing', 'baseband', 'gnodeb', 'enodeb', '\\bvolte\\b', 'salt typhoon',
        'sim.?swap', 'simjacker', 'mobile (?:carrier|operator|network)', 'cellular network',
        'lawful intercept', 'o-?ran\\b', 'open5gs', 'srsran', 'roaming fraud', 'packet core',
        '\\bims core\\b', 'mvno', 'gsm network', 'lte network',
    ].join('|'),
    'i',
);

interface RssItem { title?: string; link?: unknown; description?: string; category?: unknown; pubDate?: string }

/** RSS link is a string; Atom link is an object with @_href. Normalise. */
function linkOf(raw: unknown): string {
    if (typeof raw === 'string') return raw.trim();
    if (raw && typeof raw === 'object' && '@_href' in raw) return String((raw as Record<string, unknown>)['@_href'] ?? '').trim();
    return '';
}

const matchedTerms = (text: string): string[] => {
    const out = new Set<string>();
    for (const m of text.matchAll(new RegExp(TELCO_RE.source, 'gi'))) out.add(m[0].toLowerCase());
    return Array.from(out).slice(0, 6);
};

function stripHtml(s: string): string {
    return s.replace(/<[^>]*>/g, ' ').replace(/&[a-z]+;/gi, ' ').replace(/\s+/g, ' ').trim();
}

async function fetchFeed(url: string): Promise<RssItem[]> {
    const res = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/rss+xml, application/xml, text/xml' } });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    const xml = await res.text();
    const parsed = new XMLParser({ ignoreAttributes: false, trimValues: true }).parse(xml);
    const channel = parsed?.rss?.channel ?? parsed?.feed ?? {};
    const items = channel.item ?? channel.entry ?? [];
    return Array.isArray(items) ? items : [items];
}

export interface TelcoNewsResult { processed: number; failed: number; errors: string[] }

export async function syncTelcoNews(): Promise<TelcoNewsResult> {
    const result: TelcoNewsResult = { processed: 0, failed: 0, errors: [] };
    const rows: NewTelcoAdvisory[] = [];

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
            const title = (typeof it.title === 'string' ? it.title : '').trim();
            const link = linkOf(it.link);
            if (!title || !link) continue;
            const desc = stripHtml(typeof it.description === 'string' ? it.description : '');
            const cats = Array.isArray(it.category) ? it.category.join(' ') : String(it.category ?? '');
            const haystack = `${title} ${desc} ${cats}`;
            if (!TELCO_RE.test(haystack)) continue;

            const published = it.pubDate ? new Date(it.pubDate) : null;
            rows.push({
                source: feed.key,
                externalId: link,
                title,
                url: link,
                summary: desc ? desc.slice(0, 600) : null,
                tags: ['telco', 'news', ...matchedTerms(haystack)],
                publishedAt: published && !Number.isNaN(published.getTime()) ? published : null,
            });
        }
    }

    log.info('Telco news matched', { matched: rows.length });

    for (const row of rows) {
        try {
            await db.insert(telcoAdvisories).values(row).onConflictDoUpdate({
                target: telcoAdvisories.externalId,
                set: { title: row.title, summary: row.summary, tags: row.tags, publishedAt: row.publishedAt, updatedAt: new Date() },
            });
            result.processed++;
        } catch (err) {
            result.failed++;
            if (result.errors.length < 8) result.errors.push(`upsert ${row.url}: ${(err as Error).message}`);
        }
    }

    log.info('Telco news sync done', { processed: result.processed, failed: result.failed });
    return result;
}

// Standalone runner.
export async function runTelcoNewsSync(): Promise<void> {
    try { await syncTelcoNews(); } catch (err) { log.error('Sync failed', err as Error); }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runTelcoNewsSync().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
}
