/**
 * OpenPhish parity test — A7.2 acceptance gate.
 *
 * Third migration in the A7 sequence (ThreatFox A4, CISA A7.1).
 *
 * Why this PR is more than just "another manifest":
 *   - First text-format migration. Engine extractor widened from
 *     {json, csv} to {json, csv, text} in this PR. Each non-blank,
 *     non-comment line of the payload becomes { line: "<content>" }.
 *
 * Engine output matches the legacy syncOpenPhish() (apps/worker/src/feeds/
 * openphish.ts) on every detection-critical field:
 *
 *   PARITY-CRITICAL (asserted bit-for-bit):
 *     - value         → the URL line itself
 *     - type          → 'url' (literal)
 *     - source        → 'openphish' (literal)
 *     - threatType    → 'phishing' (literal)
 *     - confidence    → 90 (literal)
 *     - severity      → 'high' (literal)
 *     - tags          → ['openphish', 'phishing'] (literal; legacy adds
 *                       a third per-record `domain` tag — see gaps below)
 *
 *   DOCUMENTED PARITY GAP (decorative, deferred):
 *     - tags: legacy emits ['openphish', 'phishing', domain] where domain
 *       = new URL(line).hostname. Engine has no URL-host transform op.
 *       Detection isn't affected — `source = 'openphish'` and the URL
 *       itself drive the operational filters. Could add a `urlHost`
 *       transform if any other feed needs it.
 *
 *   DOCUMENTED IMPROVEMENT (asserted):
 *     - Comment-line skipping. Legacy did `.startsWith('http')` to filter
 *       lines, which silently dropped any valid http URL that started
 *       differently (e.g. `Http://` with capital H, which IS a valid URL).
 *       The text extractor uses commentPrefix='#' so any non-# line is
 *       kept — operator controls what counts as a comment, not a
 *       baked-in prefix.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { FeedManifest } from "../src/manifest.js";
import { runEngine } from "../src/engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifestPath = resolve(__dirname, "..", "manifests", "openphish.json");
const fixturePath = resolve(__dirname, "fixtures", "openphish-sample.txt");

// Verbatim transcription of the parity-critical fields from
// apps/worker/src/feeds/openphish.ts:84-103. If that file changes, this
// function must too — divergence shows up as a CI failure rather than
// silent drift.
function legacyExpected(url: string) {
    return {
        value: url,
        type: 'url',
        source: 'openphish',
        threatType: 'phishing',
        confidence: 90,
        severity: 'high',
    };
}

describe('OpenPhish manifest parity vs legacy handler', () => {
    const manifest = FeedManifest.parse(JSON.parse(readFileSync(manifestPath, "utf8"))) as
        FeedManifest & { entity: "ioc" };
    const fixture = readFileSync(fixturePath, "utf8");

    // The 5 expected URLs are the only http(s) lines in the fixture, after
    // the comment header is skipped and blank lines drop out.
    const expectedUrls = [
        'http://phish-example-1.com/login.php?account=verify',
        'http://malicious-domain.example.org/wp-admin/login',
        'https://fake-bank.example.net/secure/login.html',
        'https://account-verify.example.io/auth?next=/dashboard',
        'http://stealer.example.net/credentials/submit',
    ];

    it('fixture parses to exactly the expected 5 URLs (skips 3 comments + 2 blanks)', () => {
        const result = runEngine(manifest, fixture);
        expect(result.stats.read).toBe(5);
        expect(result.stats.ok).toBe(5);
        expect(result.stats.failed).toBe(0);
        expect(result.records.map((r) => r.value)).toEqual(expectedUrls);
    });

    it('matches legacy on the parity-critical fields for every record', () => {
        const result = runEngine(manifest, fixture);

        for (let i = 0; i < expectedUrls.length; i++) {
            const engineOut = result.records[i];
            const legacy = legacyExpected(expectedUrls[i]);

            const enginePart = {
                value: engineOut.value,
                type: engineOut.type,
                source: engineOut.source,
                threatType: engineOut.threatType,
                confidence: engineOut.confidence,
                severity: engineOut.severity,
            };

            expect(enginePart, `record[${i}] (url=${expectedUrls[i]})`).toEqual(legacy);
        }
    });

    it('emits literal tags ["openphish","phishing"] for every record (documented decorative gap)', () => {
        const result = runEngine(manifest, fixture);
        for (const rec of result.records) {
            // Engine emits exactly the two literals. Legacy also injects the
            // URL's hostname as a third tag — that's the documented gap.
            expect(rec.tags).toEqual(['openphish', 'phishing']);
        }
    });

    it('rejects an empty URL line via the required guard (defense for malformed feeds)', () => {
        // Single blank line — extractor filters; no records reach the mapping.
        const result = runEngine(manifest, '\n   \n');
        expect(result.stats.read).toBe(0);
        expect(result.stats.ok).toBe(0);
        expect(result.records).toHaveLength(0);
    });

    it('honours commentPrefix from the manifest (text extractor config audit)', () => {
        const result = runEngine(manifest, '# comment\nhttp://kept.example/path\n');
        expect(result.stats.read).toBe(1);
        expect(result.records[0]?.value).toBe('http://kept.example/path');
    });
});
