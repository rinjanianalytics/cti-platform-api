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
    const m = v.match(new RegExp(pattern));
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
};

export function applyTransforms(value: unknown, steps: TransformStep[]): unknown {
  return steps.reduce((acc, step) => REGISTRY[step.op](acc, step.arg), value);
}
