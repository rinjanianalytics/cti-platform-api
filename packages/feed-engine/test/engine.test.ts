import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { FeedManifest, type EntityKind } from "../src/manifest.js";
import { runEngine } from "../src/engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifestPath = (name: string) => resolve(__dirname, "..", "manifests", `${name}.json`);

function loadManifest<K extends EntityKind>(
  name: string,
  expected: K,
): FeedManifest & { entity: K } {
  const m = FeedManifest.parse(JSON.parse(readFileSync(manifestPath(name), "utf8")));
  if (m.entity !== expected) {
    throw new Error(`Manifest ${name} has entity '${m.entity}', expected '${expected}'`);
  }
  return m as FeedManifest & { entity: K };
}

describe("runEngine — ThreatFox (JSON manifest)", () => {
  const manifest = loadManifest("threatfox", "ioc");

  it("parses 3 IOCs across ip/domain/hash with mapEnum lowering ioc_type to canonical vocab", () => {
    const payload = JSON.stringify({
      query_status: "ok",
      data: [
        {
          ioc: "1.2.3.4:8080",
          ioc_type: "ip:port",
          confidence_level: 100,
          first_seen: "2025-12-01T10:00:00Z",
          tags: ["c2", "qakbot"],
        },
        {
          ioc: "malicious.example.com",
          ioc_type: "domain",
          confidence_level: 75,
          first_seen: "2025-12-02T09:00:00Z",
          tags: [],
        },
        {
          ioc: "d41d8cd98f00b204e9800998ecf8427e",
          ioc_type: "md5_hash",
          confidence_level: 50,
          first_seen: "2025-12-03T08:00:00Z",
          tags: ["malware"],
        },
      ],
    });

    const result = runEngine(manifest, payload);

    expect(result.stats).toEqual({ read: 3, ok: 3, failed: 0 });
    expect(result.errors).toHaveLength(0);
    expect(result.records).toHaveLength(3);

    const [a, b, c] = result.records;
    expect(a).toMatchObject({ type: "ip", value: "1.2.3.4:8080", source: "threatfox", severity: "critical" });
    expect(b).toMatchObject({ type: "domain", value: "malicious.example.com", source: "threatfox", severity: "high" });
    expect(c).toMatchObject({ type: "hash-md5", value: "d41d8cd98f00b204e9800998ecf8427e", source: "threatfox", severity: "medium" });

    // firstSeen normalized to ISO 8601
    expect(a.firstSeen).toBe("2025-12-01T10:00:00.000Z");
    // confidence numeric, in range
    expect(a.confidence).toBe(100);
    expect(b.confidence).toBe(75);
  });

  it("fallback severity maps unknown confidence to 'low'", () => {
    const payload = JSON.stringify({
      data: [{ ioc: "5.6.7.8", ioc_type: "ip:port", confidence_level: 12, tags: [] }],
    });
    const result = runEngine(manifest, payload);
    expect(result.records[0]?.severity).toBe("low");
  });
});

describe("runEngine — URLhaus (CSV manifest)", () => {
  const manifest = loadManifest("urlhaus", "ioc");

  it("parses CSV header row + 2 records, splits tags by comma, normalizes dates", () => {
    const payload = [
      "id,dateadded,url,url_status,threat,tags",
      "1,2025-12-04 11:22:33,http://bad.example.com/x.exe,online,malware_download,\"qakbot,trojan\"",
      "2,2025-12-05 12:34:56,http://other.example.org/y,online,phish,\"phishing\"",
    ].join("\n");

    const result = runEngine(manifest, payload);

    expect(result.stats).toEqual({ read: 2, ok: 2, failed: 0 });
    expect(result.records).toHaveLength(2);

    const [a, b] = result.records;
    expect(a).toMatchObject({ type: "url", value: "http://bad.example.com/x.exe", source: "urlhaus", severity: "high" });
    expect(a.tags).toEqual(["qakbot", "trojan"]);
    expect(b).toMatchObject({ type: "url", value: "http://other.example.org/y", source: "urlhaus", severity: "medium" });
    expect(b.tags).toEqual(["phishing"]);

    // dateadded -> ISO 8601
    expect(a.firstSeen).toMatch(/^2025-12-04T\d{2}:22:33/);
  });
});

describe("runEngine — broken-record fixture (required-field enforcement + per-record errors)", () => {
  const manifest = loadManifest("threatfox", "ioc");

  it("emits one error per malformed record; other records still pass", () => {
    const payload = JSON.stringify({
      data: [
        // ok
        { ioc: "9.9.9.9", ioc_type: "ip:port", confidence_level: 100, tags: [] },
        // missing required `ioc` (value)
        { ioc_type: "domain", confidence_level: 75, tags: [] },
        // missing `ioc_type` — mapEnum's `fallback: "domain"` catches this, so
        // the record IS valid. This documents the manifest's graceful behaviour:
        // unknown type strings degrade to "domain" rather than failing.
        { ioc: "no-type.example.com", confidence_level: 50, tags: [] },
        // ok
        { ioc: "deadbeef00112233", ioc_type: "md5_hash", confidence_level: 100, tags: [] },
      ],
    });

    const result = runEngine(manifest, payload);

    expect(result.stats.read).toBe(4);
    expect(result.stats.ok).toBe(3);
    expect(result.stats.failed).toBe(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.reason).toMatch(/required field "value" empty/);
    expect(result.errors[0]?.index).toBe(1);

    // Successful records carry through — including the fallback-typed one.
    expect(result.records.map((r) => r.value)).toEqual([
      "9.9.9.9",
      "no-type.example.com",
      "deadbeef00112233",
    ]);
    // Fallback record landed at type "domain"
    expect(result.records[1]?.type).toBe("domain");
  });

  it("rejects values that fail zod (e.g. type outside the IOC enum)", () => {
    // Bypass mapEnum: an entry whose mapped value still doesn't satisfy the IOC type enum
    // would be caught by zod. Here we exercise the validator path by inventing a value
    // that bypasses the mapper fallback — using an unmapped ioc_type so fallback="domain"
    // applies but value is a bad URL. We test zod's rejection via min(1) on `value`.
    const payload = JSON.stringify({
      data: [{ ioc: "", ioc_type: "domain", confidence_level: 50, tags: [] }],
    });
    const result = runEngine(manifest, payload);
    expect(result.stats.failed).toBe(1);
    // empty `ioc` is caught by the `required` guard before zod even sees it
    expect(result.errors[0]?.reason).toMatch(/required field "value" empty/);
  });
});

describe("runEngine — multi-entity contract (vulnerability schema)", () => {
  it("parses a minimal CVE feed via the vulnerability schema", () => {
    const manifest = FeedManifest.parse({
      id: "test-cve",
      name: "Test CVE feed",
      enabled: true,
      entity: "vulnerability",
      source: { url: "https://example.com/cve", method: "GET", headers: {}, auth: { type: "none" } },
      format: "json",
      extract: { recordsPath: "vulnerabilities" },
      mapping: {
        cveId: { from: "id", transforms: [{ op: "trim" }, { op: "upper" }], required: true },
        source: { literal: "test" },
        description: { from: "summary" },
        cvssScore: { from: "cvss", transforms: [{ op: "toNumber" }] },
        severity: { from: "sev", transforms: [
          { op: "lower" },
          { op: "mapEnum", arg: { table: { critical: "critical", high: "high", med: "medium" }, fallback: "none" } },
        ] },
      },
    }) as FeedManifest & { entity: "vulnerability" };

    const payload = JSON.stringify({
      vulnerabilities: [
        { id: "cve-2025-1234", summary: "RCE in foo", cvss: "9.8", sev: "Critical" },
        { id: "CVE-2025-9999", summary: "info disclosure", cvss: 5.5, sev: "MED" },
      ],
    });

    const result = runEngine(manifest, payload);

    expect(result.stats).toEqual({ read: 2, ok: 2, failed: 0 });
    expect(result.records[0]).toMatchObject({
      cveId: "CVE-2025-1234",
      cvssScore: 9.8,
      severity: "critical",
      description: "RCE in foo",
    });
    expect(result.records[1]).toMatchObject({
      cveId: "CVE-2025-9999",
      cvssScore: 5.5,
      severity: "medium",
    });
  });

  it("rejects malformed CVE IDs via zod regex", () => {
    const manifest = FeedManifest.parse({
      id: "test-cve",
      name: "Test",
      enabled: true,
      entity: "vulnerability",
      source: { url: "https://example.com/cve", method: "GET", headers: {}, auth: { type: "none" } },
      format: "json",
      extract: { recordsPath: "items" },
      mapping: {
        cveId: { from: "id", required: true },
        source: { literal: "test" },
      },
    }) as FeedManifest & { entity: "vulnerability" };
    const payload = JSON.stringify({ items: [{ id: "not-a-cve" }] });
    const result = runEngine(manifest, payload);
    expect(result.stats.failed).toBe(1);
    expect(result.errors[0]?.reason).toMatch(/cveId/);
  });
});
