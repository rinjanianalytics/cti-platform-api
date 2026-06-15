/**
 * ThreatFox parity test — A4 acceptance gate.
 *
 * Runs the committed `manifests/threatfox.json` against a synthetic API-shape
 * payload and asserts the engine's output is equivalent to what the legacy
 * `apps/worker/src/feeds/threatfox.ts` handler would produce for the SAME
 * payload, on the fields that drive detection / decay / display:
 *
 *   PARITY-CRITICAL (asserted bit-for-bit):
 *     - value          → ioc
 *     - source         → 'threatfox' (literal)
 *     - threatType     → mapEnum 4-key table + 'malware' fallback
 *     - confidence     → toNumber on confidence_level
 *     - severity       → bucketize on confidence_level (≥75 high, ≥50 medium, else low)
 *     - firstSeen      → toIso on first_seen
 *     - lastSeen       → toIso on last_seen (null → undefined; sink fills with now())
 *
 *   DOCUMENTED IMPROVEMENTS over legacy (intentional, not gaps):
 *     - type: engine emits `hash-md5` / `hash-sha1` / `hash-sha256`; legacy
 *       collapsed everything to the loose `hash` bucket. The split is more
 *       correct for decay (DECAY_RATES distinguishes them) and matches the
 *       current iocs.type enum.
 *     - unknown ioc_type → 'unknown' fallback fails zod validation and the
 *       record is dropped with a per-record error; legacy silently wrote
 *       'unknown' into the table.
 *
 *   DOCUMENTED PARITY GAPS (decorative, deferred to follow-up):
 *     - tags: engine emits `['threatfox', ...sourceTags]`; legacy adds
 *       `malware_printable` in the middle. Cross-field reference would need
 *       a new engine vocab feature ({{fromField}} interpolation). Detection
 *       isn't affected — the `threatfox` source filter + threatType cover
 *       the operational query paths.
 *     - metadata: legacy stuffs urlhaus_id / reporter / etc. into a
 *       non-existent `metadata` column (silently dropped at DB layer today),
 *       so there's nothing to preserve.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { FeedManifest, type CanonicalIoc } from "../src/manifest.js";
import { runEngine } from "../src/engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifestPath = resolve(__dirname, "..", "manifests", "threatfox.json");
const fixturePath = resolve(__dirname, "fixtures", "threatfox-sample.json");

interface ThreatFoxIOC {
    id: string;
    ioc: string;
    threat_type: string;
    ioc_type: string;
    malware_printable: string;
    confidence_level: number;
    first_seen: string;
    last_seen: string | null;
    tags: string[] | null;
}

// Verbatim transcription of the parity-critical pieces of
// apps/worker/src/feeds/threatfox.ts. If THAT file changes, this function
// must too — diverging will surface as a test failure.
function legacyExpected(tf: ThreatFoxIOC) {
    const IOC_TYPE_MAP: Record<string, string> = {
        'ip:port': 'ip', domain: 'domain', url: 'url',
        // Legacy collapsed all hashes to 'hash'. We use the more specific
        // names here so the test asserts the documented IMPROVEMENT.
        md5_hash: 'hash-md5', sha1_hash: 'hash-sha1', sha256_hash: 'hash-sha256',
    };
    const THREAT_TYPE_MAP: Record<string, string> = {
        botnet_cc: 'c2', payload_delivery: 'malware',
        ransomware_payment_site: 'ransomware', phishing: 'phishing',
    };

    let severity: 'low' | 'medium' | 'high';
    if (tf.confidence_level >= 75) severity = 'high';
    else if (tf.confidence_level >= 50) severity = 'medium';
    else severity = 'low';

    return {
        type: IOC_TYPE_MAP[tf.ioc_type] ?? 'unknown',
        value: tf.ioc,
        source: 'threatfox',
        threatType: THREAT_TYPE_MAP[tf.threat_type] ?? 'malware',
        confidence: tf.confidence_level,
        severity,
        firstSeen: new Date(tf.first_seen).toISOString(),
        lastSeen: tf.last_seen ? new Date(tf.last_seen).toISOString() : undefined,
    };
}

describe("ThreatFox manifest parity vs legacy handler", () => {
    const manifest = FeedManifest.parse(JSON.parse(readFileSync(manifestPath, "utf8"))) as
        FeedManifest & { entity: "ioc" };
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
        query_status: string;
        data: ThreatFoxIOC[];
    };

    it("fixture is well-formed and exercises all 5 IOC type variants + the threat-type table", () => {
        expect(fixture.query_status).toBe("ok");
        expect(fixture.data).toHaveLength(5);
        const iocTypes = new Set(fixture.data.map((d) => d.ioc_type));
        expect(iocTypes).toEqual(new Set(["ip:port", "domain", "url", "md5_hash", "sha256_hash"]));
        const threatTypes = new Set(fixture.data.map((d) => d.threat_type));
        expect(threatTypes.size).toBeGreaterThanOrEqual(3);
    });

    it("engine processes every record without errors", () => {
        const result = runEngine(manifest, JSON.stringify(fixture));
        expect(result.stats.read).toBe(5);
        expect(result.stats.ok).toBe(5);
        expect(result.stats.failed).toBe(0);
        expect(result.errors).toHaveLength(0);
    });

    it("matches legacy on the parity-critical fields for every record", () => {
        const result = runEngine(manifest, JSON.stringify(fixture));

        for (let i = 0; i < fixture.data.length; i++) {
            const engineOut = result.records[i] as CanonicalIoc;
            const legacy = legacyExpected(fixture.data[i]);

            // Build the engine projection of just the parity-critical fields.
            const enginePart = {
                type: engineOut.type,
                value: engineOut.value,
                source: engineOut.source,
                threatType: engineOut.threatType,
                confidence: engineOut.confidence,
                severity: engineOut.severity,
                firstSeen: engineOut.firstSeen,
                lastSeen: engineOut.lastSeen,
            };

            expect(enginePart, `record[${i}] (ioc=${fixture.data[i].ioc})`).toEqual(legacy);
        }
    });

    it("emits tags prefixed with 'threatfox' (documented partial parity)", () => {
        const result = runEngine(manifest, JSON.stringify(fixture));

        // Record 0: source tags ["qakbot","c2","windows"] → ["threatfox","qakbot","c2","windows"]
        expect(result.records[0]?.tags).toEqual(["threatfox", "qakbot", "c2", "windows"]);

        // Record 2: source tags null → prepend treats null as []-equivalent and produces
        // just the prefix. The undefined-source guard sits AFTER transforms in
        // engine.ts:33, so `prepend` can legitimately synthesise a value.
        // Legacy here would have produced ["threatfox","Unknown"]; engine produces
        // ["threatfox"]. The "Unknown" tag is the malware_printable gap documented
        // in the file header — decorative, not detection-relevant.
        expect(result.records[2]?.tags).toEqual(["threatfox"]);

        // Record 4: source tags [] → ["threatfox"]
        expect(result.records[4]?.tags).toEqual(["threatfox"]);

        // None of the engine tag arrays include the legacy-injected `malware_printable`.
        // This is the one documented parity gap — see test file header.
        for (const r of result.records) {
            expect(r.tags).not.toContain("QakBot");
            expect(r.tags).not.toContain("Emotet");
            expect(r.tags).not.toContain("LockBit");
        }
    });

    it("emits more specific hash types than legacy (documented improvement)", () => {
        const result = runEngine(manifest, JSON.stringify(fixture));

        // md5_hash record → engine emits hash-md5; legacy would write 'hash'
        const md5Record = result.records.find((r) => r.value === "d41d8cd98f00b204e9800998ecf8427e");
        expect(md5Record?.type).toBe("hash-md5");

        // sha256_hash record → engine emits hash-sha256; legacy would write 'hash'
        const shaRecord = result.records.find(
            (r) => r.value === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        expect(shaRecord?.type).toBe("hash-sha256");
    });

    it("drops records with unknown ioc_type instead of writing 'unknown' (documented improvement)", () => {
        // Synthesise a payload with a single unknown ioc_type.
        const payload = JSON.stringify({
            query_status: "ok",
            data: [
                {
                    id: "X", ioc: "value-with-unknown-type", threat_type: "phishing",
                    ioc_type: "novel_type_2030", malware_printable: "Test",
                    confidence_level: 80, first_seen: "2026-06-15 00:00:00 UTC",
                    last_seen: null, tags: [],
                },
            ],
        });
        const result = runEngine(manifest, payload);
        // The mapEnum fallback is 'unknown', which fails the IOC type enum →
        // record drops with a per-record zod error. Legacy would have inserted
        // it with type='unknown'.
        expect(result.stats.failed).toBe(1);
        expect(result.errors[0]?.reason).toMatch(/type/);
        expect(result.records).toHaveLength(0);
    });
});
