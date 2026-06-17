import type { TransformStep } from "./manifest.js";

type TransformFn = (value: unknown, arg: unknown) => unknown;

/**
 * Every transform is a pure function. The LLM mapper may only emit ops from
 * this registry, so its output is always executable and verifiable — it cannot
 * invent code paths.
 */
const REGISTRY: Record<TransformStep["op"], TransformFn> = {
  trim: (v) => (typeof v === "string" ? v.trim() : v),
  lower: (v) => (typeof v === "string" ? v.toLowerCase() : v),
  upper: (v) => (typeof v === "string" ? v.toUpperCase() : v),

  toNumber: (v) => {
    if (v === null || v === undefined || v === "") return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  },

  // best-effort ISO 8601; passes through anything Date can parse
  toIso: (v) => {
    if (v === null || v === undefined || v === "") return undefined;
    const d = new Date(v as string);
    return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
  },

  // arg: fallback value used when current value is null/undefined/""
  default: (v, arg) => (v === null || v === undefined || v === "" ? arg : v),

  // arg: { table: Record<string,string>, fallback?: string }
  mapEnum: (v, arg) => {
    const { table, fallback } = (arg ?? {}) as { table?: Record<string, string>; fallback?: string };
    const key = String(v ?? "");
    return table?.[key] ?? fallback ?? v;
  },

  // arg: { pattern: string, group?: number }
  regexExtract: (v, arg) => {
    if (typeof v !== "string") return v;
    const { pattern, group = 0 } = (arg ?? {}) as { pattern?: string; group?: number };
    if (!pattern) return v;
    // Guard `new RegExp` so a malformed manifest pattern yields "no match"
    // instead of throwing — keeps applyTransforms a TOTAL function (it never
    // throws on any input), so a bad pattern can't take down a record.
    let re: RegExp;
    try { re = new RegExp(pattern); } catch { return undefined; }
    const m = v.match(re);
    return m ? m[group] : undefined;
  },

  // arg: { sep: string } -> returns string[]
  split: (v, arg) => {
    if (typeof v !== "string") return v;
    const { sep = "," } = (arg ?? {}) as { sep?: string };
    return v.split(sep).map((s) => s.trim()).filter(Boolean);
  },

  // arg: string prefix to strip
  stripPrefix: (v, arg) => {
    if (typeof v !== "string" || typeof arg !== "string") return v;
    return v.startsWith(arg) ? v.slice(arg.length) : v;
  },

  // arg: ignored — turns "" into undefined so `default`/`required` behave
  coalesce: (v) => (v === "" || v === null ? undefined : v),

  // arg: { ranges: Array<{min?: number, max?: number, value: string}>, fallback?: string }
  // First matching range wins (inclusive bounds). Use for numeric→enum mappings
  // like "confidence >= 75 → high, >= 50 → medium, else low" that mapEnum can't
  // express because it only does exact-key matches.
  bucketize: (v, arg) => {
    if (v === null || v === undefined || v === "") return undefined;
    const n = Number(v);
    if (!Number.isFinite(n)) return undefined;
    const { ranges, fallback } = (arg ?? {}) as {
      ranges?: Array<{ min?: number; max?: number; value: string }>;
      fallback?: string;
    };
    if (!Array.isArray(ranges)) return fallback;
    for (const r of ranges) {
      const minOk = r.min === undefined || n >= r.min;
      const maxOk = r.max === undefined || n <= r.max;
      if (minOk && maxOk) return r.value;
    }
    return fallback;
  },

  // arg: string | string[] — items to prepend to the current value (treated as
  // an array; scalars are wrapped). Use for tag prefixes like `['threatfox', ...]`
  // that mapEnum + literal can't compose because they target one output field.
  prepend: (v, arg) => {
    const list = Array.isArray(v) ? v
      : (v === undefined || v === null || v === "") ? []
      : [v];
    const pre = Array.isArray(arg) ? arg
      : (arg === undefined || arg === null) ? []
      : [arg];
    return [...pre, ...list];
  },
};

export function applyTransforms(value: unknown, steps: TransformStep[]): unknown {
  return steps.reduce((acc, step) => REGISTRY[step.op](acc, step.arg), value);
}
