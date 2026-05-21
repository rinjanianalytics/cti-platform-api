/**
 * V3 Worker Entry Point - Standalone Mode
 *
 * Runs all intel feed workers independently.
 * Syncs directly from public threat intel sources using the
 * full 10-feed orchestrator with per-feed intervals.
 */

// MUST be the very first import — see boot-env.ts for why.
import './boot-env.js';

import { feeds, runAllFeeds, type FeedName } from './feeds/index.js';

const FEED_NAMES = Object.keys(feeds) as FeedName[];
const FEED_COUNT = FEED_NAMES.length;

const feedList = FEED_NAMES.map(k => feeds[k].name).join(', ');
console.log(`
╔═══════════════════════════════════════════════════════════╗
║         V3 Threat Intel Worker (Standalone)               ║
╠═══════════════════════════════════════════════════════════╣
║  Mode:   Full feed sync (${FEED_COUNT} feeds)${' '.repeat(Math.max(0, 28 - String(FEED_COUNT).length))}║
║  Feeds:  ${feedList.slice(0, 49)}${' '.repeat(Math.max(0, 49 - feedList.slice(0, 49).length))}║
╚═══════════════════════════════════════════════════════════╝
`);

console.log(`[Worker] Full feed list: ${feedList}`);

/**
 * Start daemon mode — runs all feeds initially, then each on its own interval
 */
async function startDaemon() {
    console.log('[Worker] Starting daemon mode...\n');

    // Run all feeds immediately on startup
    await runAllFeeds();

    // Set up per-feed intervals (each feed runs on its own schedule)
    for (const [key, feed] of Object.entries(feeds)) {
        const intervalMin = (feed.interval / 60000).toFixed(0);
        console.log(`[Worker] Scheduling ${feed.name} every ${intervalMin}min`);
        setInterval(async () => {
            console.log(`[Worker] Scheduled sync: ${feed.name}`);
            try {
                await feed.sync();
            } catch (error) {
                console.error(`[Worker] Feed sync failed: ${feed.name}`, error);
            }
        }, feed.interval);
    }

    console.log(`\n[Worker] Daemon running — ${FEED_COUNT} feeds on independent intervals.`);
}

/**
 * Run once mode (for cron jobs)
 */
async function runOnce() {
    console.log('[Worker] Running in one-shot mode...\n');
    await runAllFeeds();
    console.log('[Worker] One-shot complete. Exiting.');
    process.exit(0);
}

// Main
const mode = process.argv.includes('--once') ? 'once' : 'daemon';

if (mode === 'once') {
    runOnce().catch((error) => {
        console.error('[Worker] Fatal error:', error);
        process.exit(1);
    });
} else {
    startDaemon().catch((error) => {
        console.error('[Worker] Fatal error:', error);
        process.exit(1);
    });
}
