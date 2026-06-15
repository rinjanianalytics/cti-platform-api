import type { FeedManifest } from "./manifest.js";

/** Resolve a dot-path like "a.b.c" against an object. */
export function getPath(obj: unknown, path: string | undefined): unknown {
  if (!path) return obj;
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object" && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj);
}

/** Minimal but quote-aware CSV parser (handles "quoted, commas" and "" escapes). */
function parseCsv(text: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === delimiter) { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (c === "\r") { /* skip */ }
    else field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.length > 1 || (r.length === 1 && r[0] !== ""));
}

/** Returns an array of record objects, format-agnostic. */
export function extractRecords(manifest: FeedManifest, payload: string): Record<string, unknown>[] {
  if (manifest.format === "json") {
    const parsed = JSON.parse(payload);
    const arr = getPath(parsed, manifest.extract.recordsPath);
    if (!Array.isArray(arr)) {
      throw new Error(`recordsPath "${manifest.extract.recordsPath}" did not resolve to an array`);
    }
    return arr as Record<string, unknown>[];
  }

  if (manifest.format === "text") {
    // Plain-text line-per-record: each non-blank, non-comment line becomes
    // { line: "<content>" }. Used by feeds like OpenPhish's feed.txt that
    // ship a flat list of values with no structure beyond newlines.
    //
    // Comment prefix configurable so feeds using `#`, `//`, or `;` all work
    // through the same path. Empty default means "no comment lines".
    const cfg = manifest.extract.text ?? { commentPrefix: "" };
    const lines = payload.split("\n");
    return lines
      .map((l) => l.replace(/\r$/, "").trim())
      .filter((l) => l.length > 0 && (!cfg.commentPrefix || !l.startsWith(cfg.commentPrefix)))
      .map((l) => ({ line: l }));
  }

  // csv
  const cfg = manifest.extract.csv ?? { delimiter: ",", hasHeader: true };
  const rows = parseCsv(payload, cfg.delimiter);
  if (rows.length === 0) return [];
  if (cfg.hasHeader) {
    const header = rows[0].map((h) => h.trim());
    return rows.slice(1).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
  }
  // headerless: expose positional keys c0, c1, ...
  return rows.map((r) => Object.fromEntries(r.map((v, i) => [`c${i}`, v])));
}
