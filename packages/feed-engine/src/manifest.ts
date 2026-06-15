import { z } from "zod";

/**
 * Per-entity zod schemas. Each one is a parser-output contract — the minimum
 * required-field set + the optional fields manifests can populate. The drizzle
 * tables in @rinjani/db remain the canonical source of truth; these schemas
 * exist so the engine can validate manifest output without taking a DB dep.
 *
 * When a new column is added in @rinjani/db that a manifest needs to populate,
 * widen the matching schema here. Drop columns that only the worker sink fills
 * (e.g. enrichment_*, decayed_at, risk_score) — manifests never write them.
 */

const IsoDate = z.string(); // ISO 8601 — extractor normalizes via toIso transform

/** ---------- IOC ---------- */
/** packages/db/src/schema/feeds.ts → iocs */
export const CanonicalIoc = z.object({
  // Aligned with DECAY_RATES keys (apps/api/src/services/confidenceDecay.ts).
  type: z.enum([
    "ip",
    "domain",
    "hostname",
    "url",
    "hash-md5",
    "hash-sha1",
    "hash-sha256",
    "email",
  ]),
  value: z.string().min(1),
  source: z.string().min(1),
  threatType: z.string().optional(),
  confidence: z.number().int().min(0).max(100).optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  tags: z.array(z.string()).default([]),
  firstSeen: IsoDate.optional(),
  lastSeen: IsoDate.optional(),
  pulseId: z.string().optional(),
});
export type CanonicalIoc = z.infer<typeof CanonicalIoc>;

/** ---------- Vulnerability (CVE) ---------- */
/** packages/db/src/schema/feeds.ts → vulnerabilities */
export const CanonicalVulnerability = z.object({
  cveId: z.string().min(1).regex(/^CVE-\d{4}-\d{4,}$/i),
  source: z.string().min(1),
  description: z.string().optional(),
  cvssScore: z.number().min(0).max(10).optional(),
  cvssVector: z.string().optional(),
  severity: z.enum(["none", "low", "medium", "high", "critical"]).optional(),
  cweId: z.string().optional(),
  isExploited: z.boolean().optional(),
  epssScore: z.number().min(0).max(1).optional(),
  epssPercentile: z.number().min(0).max(1).optional(),
  vendorProject: z.string().optional(),
  product: z.string().optional(),
  references: z.array(z.string()).default([]),
  publishedDate: IsoDate.optional(),
  lastModified: IsoDate.optional(),
});
export type CanonicalVulnerability = z.infer<typeof CanonicalVulnerability>;

/** ---------- Threat Actor ---------- */
/** packages/db/src/schema/threats.ts → threat_actors */
export const CanonicalThreatActor = z.object({
  name: z.string().min(1),
  source: z.string().min(1),
  description: z.string().optional(),
  aliases: z.array(z.string()).default([]),
  sophistication: z.string().optional(),
  resourceLevel: z.string().optional(),
  primaryMotivation: z.string().optional(),
  secondaryMotivations: z.array(z.string()).default([]),
  goals: z.array(z.string()).default([]),
  labels: z.array(z.string()).default([]),
  country: z.string().optional(),
  firstSeen: IsoDate.optional(),
  lastSeen: IsoDate.optional(),
});
export type CanonicalThreatActor = z.infer<typeof CanonicalThreatActor>;

/** ---------- Malware ---------- */
/** packages/db/src/schema/threats.ts → malware */
export const CanonicalMalware = z.object({
  name: z.string().min(1),
  source: z.string().min(1),
  description: z.string().optional(),
  aliases: z.array(z.string()).default([]),
  malwareTypes: z.array(z.string()).default([]),
  isFamily: z.boolean().optional(),
  capabilities: z.array(z.string()).default([]),
  labels: z.array(z.string()).default([]),
});
export type CanonicalMalware = z.infer<typeof CanonicalMalware>;

/** ---------- Campaign ---------- */
/** packages/db/src/schema/stixEntities.ts → campaigns */
export const CanonicalCampaign = z.object({
  name: z.string().min(1),
  source: z.string().min(1),
  description: z.string().optional(),
  aliases: z.array(z.string()).default([]),
  objective: z.string().optional(),
  labels: z.array(z.string()).default([]),
  firstSeen: IsoDate.optional(),
  lastSeen: IsoDate.optional(),
});
export type CanonicalCampaign = z.infer<typeof CanonicalCampaign>;

/** ---------- Course of Action ---------- */
/** packages/db/src/schema/stixEntities.ts → courses_of_action */
export const CanonicalCourseOfAction = z.object({
  name: z.string().min(1),
  source: z.string().min(1),
  description: z.string().optional(),
  actionType: z.string().optional(),
  actionDescription: z.string().optional(),
  labels: z.array(z.string()).default([]),
});
export type CanonicalCourseOfAction = z.infer<typeof CanonicalCourseOfAction>;

/** ---------- Infrastructure ---------- */
/** packages/db/src/schema/stixEntities.ts → infrastructure */
export const CanonicalInfrastructure = z.object({
  name: z.string().min(1),
  source: z.string().min(1),
  description: z.string().optional(),
  infrastructureTypes: z.array(z.string()).default([]),
  aliases: z.array(z.string()).default([]),
  labels: z.array(z.string()).default([]),
  firstSeen: IsoDate.optional(),
  lastSeen: IsoDate.optional(),
});
export type CanonicalInfrastructure = z.infer<typeof CanonicalInfrastructure>;

/** ---------- Technique (MITRE ATT&CK) ---------- */
/** packages/db/src/schema/mitre.ts → techniques */
export const CanonicalTechnique = z.object({
  // T1059, T1059.001
  mitreId: z.string().regex(/^T\d{4}(\.\d{3})?$/),
  source: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  detection: z.string().optional(),
  platforms: z.array(z.string()).default([]),
  permissions: z.array(z.string()).default([]),
  dataSources: z.array(z.string()).default([]),
  isSubtechnique: z.boolean().optional(),
  parentId: z.string().optional(),
  tacticIds: z.array(z.string()).default([]),
  url: z.string().url().optional(),
});
export type CanonicalTechnique = z.infer<typeof CanonicalTechnique>;

/** ---------- Tool (MITRE) ---------- */
/** packages/db/src/schema/mitre.ts → tools */
export const CanonicalTool = z.object({
  // S0001, S0002 — also accepts arbitrary IDs since `mitre_id` is nullable in db.
  mitreId: z.string().optional(),
  source: z.string().min(1),
  name: z.string().min(1),
  aliases: z.array(z.string()).default([]),
  description: z.string().optional(),
  type: z.string().optional(),
  platforms: z.array(z.string()).default([]),
  techniqueIds: z.array(z.string()).default([]),
  url: z.string().url().optional(),
});
export type CanonicalTool = z.infer<typeof CanonicalTool>;

/** ---------- Entity registry ---------- */
export const ENTITY_SCHEMAS = {
  ioc: CanonicalIoc,
  vulnerability: CanonicalVulnerability,
  threat_actor: CanonicalThreatActor,
  malware: CanonicalMalware,
  campaign: CanonicalCampaign,
  course_of_action: CanonicalCourseOfAction,
  infrastructure: CanonicalInfrastructure,
  technique: CanonicalTechnique,
  tool: CanonicalTool,
} as const;
export type EntityKind = keyof typeof ENTITY_SCHEMAS;

/** One transform step applied to a single field value, left-to-right. */
export const TransformStep = z.object({
  op: z.enum([
    "trim", "lower", "upper", "toNumber", "toIso",
    "default", "mapEnum", "regexExtract", "split", "stripPrefix", "coalesce",
  ]),
  // op-specific args (kept loose on purpose; validated per-op in transforms.ts)
  arg: z.unknown().optional(),
});
export type TransformStep = z.infer<typeof TransformStep>;

/** Map ONE canonical field from a source record. */
export const FieldMapping = z.object({
  from: z.string().optional(),        // dot-path into the source record, e.g. "data.ioc_type"
  literal: z.unknown().optional(),    // or a constant (e.g. source name)
  transforms: z.array(TransformStep).default([]),
  required: z.boolean().default(false),
});
export type FieldMapping = z.infer<typeof FieldMapping>;

export const FeedManifest = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean().default(true),
  entity: z.enum([
    "ioc",
    "vulnerability",
    "threat_actor",
    "malware",
    "campaign",
    "course_of_action",
    "infrastructure",
    "technique",
    "tool",
  ]),
  source: z.object({
    url: z.string().url(),
    method: z.enum(["GET", "POST"]).default("GET"),
    headers: z.record(z.string()).default({}),
    auth: z
      .object({ type: z.enum(["none", "bearer", "apiKeyHeader"]).default("none"), header: z.string().optional() })
      .default({ type: "none" }),
  }),
  format: z.enum(["json", "csv"]),
  extract: z.object({
    recordsPath: z.string().optional(),                  // json: dot-path to the array of records
    csv: z.object({ delimiter: z.string().default(","), hasHeader: z.boolean().default(true) }).optional(),
  }),
  // canonicalField -> how to build it
  mapping: z.record(FieldMapping),
});
export type FeedManifest = z.infer<typeof FeedManifest>;
