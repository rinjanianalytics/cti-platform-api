import { z } from "zod";
import { ENTITY_SCHEMAS, type EntityKind, type FeedManifest } from "./manifest.js";
import { applyTransforms } from "./transforms.js";
import { extractRecords, getPath } from "./extract.js";

export interface EngineResult<K extends EntityKind = EntityKind> {
  records: z.infer<(typeof ENTITY_SCHEMAS)[K]>[];
  errors: { index: number; reason: string }[];
  stats: { read: number; ok: number; failed: number };
}

function buildField(record: Record<string, unknown>, mapping: FeedManifest["mapping"][string]) {
  const raw = mapping.from !== undefined ? getPath(record, mapping.from) : mapping.literal;
  return applyTransforms(raw, mapping.transforms);
}

/**
 * Run a manifest against an already-fetched payload string.
 * Pure & deterministic: no network, no store — fetch and upsert live around it,
 * exactly like the split between feed-sync and ioc-enrichment workers today.
 */
export function runEngine<K extends EntityKind = EntityKind>(
  manifest: FeedManifest & { entity: K },
  payload: string,
): EngineResult<K> {
  const schema = ENTITY_SCHEMAS[manifest.entity];
  const raws = extractRecords(manifest, payload);

  const records: EngineResult<K>["records"] = [];
  const errors: EngineResult<K>["errors"] = [];

  raws.forEach((record, index) => {
    try {
      const candidate: Record<string, unknown> = {};
      for (const [field, m] of Object.entries(manifest.mapping)) {
        const value = buildField(record, m);
        if (value === undefined || value === null || value === "") {
          if (m.required) throw new Error(`required field "${field}" empty`);
          continue;
        }
        candidate[field] = value;
      }
      const parsed = schema.safeParse(candidate);
      if (!parsed.success) {
        throw new Error(parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      }
      records.push(parsed.data as EngineResult<K>["records"][number]);
    } catch (e) {
      errors.push({ index, reason: e instanceof Error ? e.message : String(e) });
    }
  });

  return {
    records,
    errors,
    stats: { read: raws.length, ok: records.length, failed: errors.length },
  };
}
