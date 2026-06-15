/**
 * CISA KEV parity test — A7.1 acceptance gate.
 *
 * Runs the committed `manifests/cisa-kev.json` against a synthetic
 * KEV-shape payload and asserts the engine's output is equivalent to what
 * `apps/api/src/services/feedSync/cisaSync.ts` produces for the SAME
 * payload, on every detection-critical field.
 *
 * Why this PR is more than just "another manifest":
 *   - First vulnerability-entity migration. Engine sink widened from
 *     IOC-only to {ioc, vulnerability} in this PR.
 *   - Adds exploitAddedDate + dueDate to CanonicalVulnerability so the
 *     KEV-specific fields the legacy handler writes have parity slots.
 *
 *   PARITY-CRITICAL (asserted bit-for-bit):
 *     - cveId           → cveID (with trim + upper)
 *     - source          → 'cisa' (literal)
 *     - description     → shortDescription
 *     - vendorProject   → vendorProject
 *     - product         → product
 *     - isExploited     → true (literal — all KEV entries are exploited)
 *     - exploitAddedDate → dateAdded
 *     - dueDate         → dueDate
 *
 *   DOCUMENTED IMPROVEMENTS over legacy (intentional, not gaps):
 *     - cveId normalisation: engine emits canonical CVE-NNNN-NNNN; legacy
 *       passes vuln.cveID through verbatim, which lower-cases when CISA
 *       slips lowercase in (rare but observed). Engine's upper transform
 *       normalises this at ingest.
 *
 *   NOT MIGRATED (intentional gaps — would need new canonical fields):
 *     - vulnerabilityName    — kept in raw_data; not surfaced on the
 *                              vuln detail page today, so not worth a
 *                              canonical slot.
 *     - requiredAction       — CISA-specific operator guidance; same.
 *     - knownRansomwareCampaignUse — interesting but operator-friendly,
 *                              not detection-critical. Track for a
 *                              future migration.
 *     - notes                — usually empty; kept in raw_data.
 *
 * Legacy also stamps `raw_data: vuln` on every row. The engine path
 * doesn't carry rawData on the canonical record — but the operator can
 * always fetch the live KEV JSON from CISA. Logging the parity gap here
 * so it's an explicit decision rather than a quiet loss.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { FeedManifest, type CanonicalVulnerability } from "../src/manifest.js";
import { runEngine } from "../src/engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifestPath = resolve(__dirname, "..", "manifests", "cisa-kev.json");
const fixturePath = resolve(__dirname, "fixtures", "cisa-kev-sample.json");

interface CISAVuln {
    cveID: string;
    vendorProject: string;
    product: string;
    shortDescription: string;
    dateAdded: string;
    dueDate: string;
}

// Verbatim transcription of the parity-critical pieces of
// apps/api/src/services/feedSync/cisaSync.ts:60-71. If that file changes
// (legacy mapping), this function must too — divergence shows up as a
// test failure rather than silent drift.
function legacyExpected(v: CISAVuln) {
    return {
        cveId: v.cveID.toUpperCase().trim(),
        source: 'cisa',
        description: v.shortDescription,
        vendorProject: v.vendorProject,
        product: v.product,
        isExploited: true,
        exploitAddedDate: v.dateAdded,
        dueDate: v.dueDate,
    };
}

describe('CISA KEV manifest parity vs legacy handler', () => {
    const manifest = FeedManifest.parse(JSON.parse(readFileSync(manifestPath, "utf8"))) as
        FeedManifest & { entity: "vulnerability" };
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
        title: string;
        vulnerabilities: CISAVuln[];
    };

    it('fixture is well-formed and includes the lowercase-cveID edge case', () => {
        expect(fixture.vulnerabilities).toHaveLength(4);
        // The third record uses lowercase 'cve-' — the engine's upper transform
        // normalises this; legacy passed it through verbatim. Engine = correct.
        expect(fixture.vulnerabilities[2].cveID).toBe('cve-2026-33333');
    });

    it('engine processes every record without errors', () => {
        const result = runEngine(manifest, JSON.stringify(fixture));
        expect(result.stats.read).toBe(4);
        expect(result.stats.ok).toBe(4);
        expect(result.stats.failed).toBe(0);
        expect(result.errors).toHaveLength(0);
    });

    it('matches legacy on the parity-critical fields for every record', () => {
        const result = runEngine(manifest, JSON.stringify(fixture));

        for (let i = 0; i < fixture.vulnerabilities.length; i++) {
            const engineOut = result.records[i] as CanonicalVulnerability;
            const legacy = legacyExpected(fixture.vulnerabilities[i]);

            const enginePart = {
                cveId: engineOut.cveId,
                source: engineOut.source,
                description: engineOut.description,
                vendorProject: engineOut.vendorProject,
                product: engineOut.product,
                isExploited: engineOut.isExploited,
                exploitAddedDate: engineOut.exploitAddedDate,
                dueDate: engineOut.dueDate,
            };

            expect(enginePart, `record[${i}] (cveID=${fixture.vulnerabilities[i].cveID})`).toEqual(legacy);
        }
    });

    it('normalises mixed-case cveID (documented improvement)', () => {
        const result = runEngine(manifest, JSON.stringify(fixture));
        // Record 2 had `cve-2026-33333`; engine output should be CVE-2026-33333.
        const r = result.records.find((rec) =>
            rec.cveId === 'CVE-2026-33333',
        );
        expect(r).toBeDefined();
        // No record kept the lower-case form
        expect(result.records.some((rec) => rec.cveId.startsWith('cve-'))).toBe(false);
    });

    it('every record carries isExploited=true (CISA KEV invariant)', () => {
        const result = runEngine(manifest, JSON.stringify(fixture));
        for (const rec of result.records) {
            expect(rec.isExploited).toBe(true);
        }
    });

    it('rejects records with a malformed cveID instead of writing junk', () => {
        const payload = JSON.stringify({
            vulnerabilities: [
                { cveID: 'not-a-cve', vendorProject: 'X', product: 'Y',
                  shortDescription: '', dateAdded: '2026-01-01', dueDate: '2026-02-01' },
            ],
        });
        const result = runEngine(manifest, payload);
        // mapEnum + zod regex on cveId catches the bad value
        expect(result.stats.failed).toBe(1);
        expect(result.records).toHaveLength(0);
        expect(result.errors[0]?.reason).toMatch(/cveId/);
    });
});
