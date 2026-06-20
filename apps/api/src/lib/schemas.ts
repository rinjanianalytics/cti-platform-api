/**
 * Shared Zod Schemas
 *
 * Validated at API ingress (route) and consumed by the worker.
 * Single source of truth for request/response shapes.
 */

import { z } from 'zod';
import { auditActionEnum, entityTypeEnum } from '@rinjani/db/schema';
import { STIX_RELATIONSHIP_TYPES } from '@rinjani/core/stixVocab';

// ============================================================================
// Query Parameter Schemas (shared across route files)
// ============================================================================

/** Maximum page size allowed to prevent unbounded data pulls */
const MAX_PAGE_SIZE = 500;

/** Base pagination for any list endpoint */
export const PaginationSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(MAX_PAGE_SIZE).default(25),
});
export type Pagination = z.infer<typeof PaginationSchema>;

/** Pagination + search + sort (most common pattern) */
export const SearchQuerySchema = PaginationSchema.extend({
    q: z.string().optional(),
    sortBy: z.enum(['createdAt', 'updatedAt']).default('createdAt'),
    sortOrder: z.enum(['asc', 'desc']).default('desc'),
});
export type SearchQuery = z.infer<typeof SearchQuerySchema>;

// ── Entity-specific filter schemas ──────────────────────────────────

export const VulnFilterSchema = SearchQuerySchema.extend({
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    exploited: z.coerce.boolean().optional(),
    ransomware: z.coerce.boolean().optional(),
    vendor: z.string().optional(),
    dateFrom: z.string().optional(), // YYYY-MM-DD
    dateTo: z.string().optional(),
});
export type VulnFilter = z.infer<typeof VulnFilterSchema>;

export const IOCFilterSchema = SearchQuerySchema.extend({
    type: z.string().optional(),       // ip, domain, url, hash, email
    source: z.string().optional(),     // alienvault, abusessl, etc.
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    dateFrom: z.string().optional(),   // YYYY-MM-DD
    dateTo: z.string().optional(),
});
export type IOCFilter = z.infer<typeof IOCFilterSchema>;

export const ThreatActorFilterSchema = SearchQuerySchema.extend({
    country: z.string().optional(),
    motivation: z.string().optional(),
    sophistication: z.string().optional(),
});
export type ThreatActorFilter = z.infer<typeof ThreatActorFilterSchema>;

export const TechniqueFilterSchema = PaginationSchema.extend({
    q: z.string().optional(),
    platform: z.string().optional(),
    tactic: z.string().optional(),
}).transform(d => ({ ...d, pageSize: Math.min(d.pageSize, MAX_PAGE_SIZE) }));

export const UnifiedSearchSchema = SearchQuerySchema.extend({
    type: z.string().optional(), // ioc, vulnerability, threat-actor
});
export type UnifiedSearch = z.infer<typeof UnifiedSearchSchema>;

export const DaysQuerySchema = z.object({
    days: z.coerce.number().int().min(1).max(365).default(30),
});

// ── Graph & Neo4j schemas ───────────────────────────────────────────

/** Graph layout server-side computation params */
export const GraphLayoutSchema = z.object({
    maxIOCs: z.coerce.number().int().min(1).max(100).default(50),
    maxActors: z.coerce.number().int().min(1).max(50).default(30),
    maxCVEs: z.coerce.number().int().min(1).max(50).default(30),
    width: z.coerce.number().int().min(400).max(4000).default(1200),
    height: z.coerce.number().int().min(300).max(3000).default(800),
});

/** Neo4j fuzzy search */
export const Neo4jSearchSchema = z.object({
    q: z.string().min(1, 'Missing search query (?q=...)'),
    limit: z.coerce.number().int().min(1).max(500).default(50),
});

/** Neo4j neighborhood expand */
export const Neo4jExpandSchema = z.object({
    depth: z.coerce.number().int().min(1).max(4).default(1),
    limit: z.coerce.number().int().min(1).max(500).default(100),
});

/** Neo4j shortest path */
export const Neo4jPathSchema = z.object({
    from: z.string().min(1, '"from" is required'),
    to: z.string().min(1, '"to" is required'),
    maxDepth: z.coerce.number().int().min(1).max(10).default(6),
});

/** Vector / similar document search */
export const VectorSearchSchema = z.object({
    q: z.string().min(1, 'Query parameter "q" is required'),
    k: z.coerce.number().int().min(1).max(50).default(10),
    type: z.string().optional(),
});

/** Generic limit param (reusable across routes) */
export const LimitSchema = z.object({
    limit: z.coerce.number().int().min(1).max(10000).default(50),
});

/** Limit + offset pattern (for audit, etc.) */
export const LimitOffsetSchema = z.object({
    limit: z.coerce.number().int().min(1).max(10000).default(50),
    offset: z.coerce.number().int().min(0).default(0),
});

// ── Alert mutation schemas ──────────────────────────────────────────

/** POST /v1/alerts — create a manual alert */
export const CreateAlertSchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
    type: z.string().min(1).max(100).default('system_alert'),
    title: z.string().min(1, 'title is required').max(500),
    message: z.string().min(1, 'message is required').max(5000),
    source: z.string().max(200).optional(),
    metadata: z.record(z.unknown()).optional(),
});
export type CreateAlert = z.infer<typeof CreateAlertSchema>;

/** PUT /v1/alerts/:id — partial update */
export const UpdateAlertSchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    title: z.string().min(1).max(500).optional(),
    message: z.string().min(1).max(5000).optional(),
    metadata: z.record(z.unknown()).optional(),
    read: z.boolean().optional(),
});
export type UpdateAlert = z.infer<typeof UpdateAlertSchema>;

/** POST /v1/alerts/acknowledge — bulk acknowledge */
export const BulkAckSchema = z.object({
    ids: z.array(z.string().uuid()).min(1, 'At least one alert ID is required').max(500),
});
export type BulkAck = z.infer<typeof BulkAckSchema>;

/** POST /v1/alerts/evaluate — threshold for IOC risk evaluation */
export const EvaluateAlertSchema = z.object({
    threshold: z.coerce.number().int().min(1).max(100).default(75),
});
export type EvaluateAlert = z.infer<typeof EvaluateAlertSchema>;

// ── Admin config schemas ────────────────────────────────────────────

/** POST /admin/config/feeds — add a custom feed */
export const AddFeedSchema = z.object({
    name: z.string().min(1).max(200),
    source: z.string().min(1).max(200),
    description: z.string().max(1000).default(''),
    cron: z.string().max(50).default('0 */6 * * *'),
    enabled: z.boolean().default(true),
    category: z.enum(['high-frequency', 'ioc-feeds', 'knowledge-base', 'nexus', 'custom-api', 'rss', 'financial', 'osint']).default('custom-api'),
    url: z.string().url().optional(),
    format: z.enum(['json', 'text', 'rss', 'csv', 'stix']).optional(),
    authHeader: z.string().max(200).optional(),
    authKeyRef: z.string().max(200).optional(),
    requiresApiKey: z.string().max(200).optional(),
});
export type AddFeed = z.infer<typeof AddFeedSchema>;

/** POST /admin/config/api-keys — add a custom API key slot */
export const AddApiKeySchema = z.object({
    name: z.string().min(1).max(200),
    provider: z.string().min(1).max(200),
    envVar: z.string().min(1).max(200),
    value: z.string().optional(),
    testEndpoint: z.string().url().optional(),
    authHeaderName: z.string().max(200).optional(),
});
export type AddApiKey = z.infer<typeof AddApiKeySchema>;

/** POST /admin/config/services — add a custom service */
export const AddServiceSchema = z.object({
    name: z.string().min(1).max(200),
    envVars: z.array(z.object({
        key: z.string().min(1),
        label: z.string().min(1),
        secret: z.boolean().optional(),
    })).min(1, 'At least one envVar required'),
    values: z.record(z.string()).optional(),
});
export type AddService = z.infer<typeof AddServiceSchema>;

/** PUT /admin/config/settings/:key — update a setting value */
export const UpdateSettingSchema = z.object({
    value: z.union([z.string(), z.number(), z.boolean()]),
});
export type UpdateSetting = z.infer<typeof UpdateSettingSchema>;

// ── Federation admin schemas ────────────────────────────────────────

/** POST /admin/federation/tenants — create a new tenant */
export const CreateTenantSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    slug: z.string().min(1, 'slug is required').max(100).regex(/^[a-z0-9-]+$/, 'slug must be lowercase alphanumeric with hyphens'),
    tier: z.enum(['free', 'pro', 'enterprise']).default('free'),
    config: z.record(z.unknown()).optional(),
});
export type CreateTenant = z.infer<typeof CreateTenantSchema>;

/** POST /admin/federation/tenants/:id/peers — add a peer to a tenant */
export const AddPeerSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    url: z.string().url('url must be a valid URL'),
    apiKey: z.string().min(1, 'apiKey is required').max(500),
    trustLevel: z.enum(['full', 'limited', 'read-only']).default('read-only'),
});
export type AddPeer = z.infer<typeof AddPeerSchema>;

/** POST /admin/migrations/rollback — rollback N migrations */
export const RollbackSchema = z.object({
    count: z.coerce.number().int().min(1).max(5).default(1),
});
export type Rollback = z.infer<typeof RollbackSchema>;

/** POST /admin/scoring/rescore — batch rescore IOCs */
export const RescoreSchema = z.object({
    batchSize: z.coerce.number().int().min(1).max(500).default(100),
});
export type Rescore = z.infer<typeof RescoreSchema>;

// ── Notification route schemas ──────────────────────────────────────

/** PUT /notifications/settings — update notification preferences */
export const NotificationSettingsSchema = z.object({
    emailEnabled: z.boolean().optional(),
    emailAddress: z.string().email().nullable().optional(),
    slackEnabled: z.boolean().optional(),
    slackWebhookUrl: z.string().url().nullable().optional(),
    severityThreshold: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    notifyOnNewIOC: z.boolean().optional(),
    notifyOnNewVuln: z.boolean().optional(),
    notifyOnThreatActor: z.boolean().optional(),
});
export type NotificationSettings = z.infer<typeof NotificationSettingsSchema>;

/** POST /notifications/test/slack — test Slack webhook */
export const TestSlackSchema = z.object({
    webhookUrl: z.string().url('webhookUrl must be a valid URL'),
});
export type TestSlack = z.infer<typeof TestSlackSchema>;

/** POST /notifications/test/email — test email delivery */
export const TestEmailSchema = z.object({
    emailAddress: z.string().email('emailAddress must be a valid email'),
});
export type TestEmail = z.infer<typeof TestEmailSchema>;

/** POST /notifications/alert — manually trigger a notification */
export const ManualAlertSchema = z.object({
    type: z.enum(['ioc', 'vulnerability', 'threat_actor', 'alert']),
    severity: z.enum(['critical', 'high', 'medium', 'low']),
    title: z.string().min(1, 'title is required').max(500),
    message: z.string().min(1, 'message is required').max(5000),
    data: z.record(z.unknown()).optional(),
});
export type ManualAlert = z.infer<typeof ManualAlertSchema>;

// ── Phase 4 #1 — Extra-channel test + rule routing ─────────────────

const SEVERITY_ENUM = z.enum(['critical', 'high', 'medium', 'low']);
const NOTIF_TYPE_ENUM = z.enum(['ioc', 'vulnerability', 'threat_actor', 'alert']);
const CHANNEL_KIND_ENUM = z.enum(['slack', 'teams', 'discord', 'pagerduty', 'email', 'webhook']);

/** POST /notifications/test/{teams,discord,pagerduty} — test a single channel */
export const TestChannelWebhookSchema = z.object({
    webhookUrl: z.string().min(1).max(500),
});
export type TestChannelWebhook = z.infer<typeof TestChannelWebhookSchema>;

/** A single routing rule — used by POST /notifications/evaluate-rules and /dispatch */
const NotificationRuleSchema = z.object({
    name: z.string().min(1).max(200),
    enabled: z.boolean().default(true),
    match: z.object({
        severityIn: z.array(SEVERITY_ENUM).optional(),
        typeIn: z.array(NOTIF_TYPE_ENUM).optional(),
        requireData: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
    }),
    channels: z.array(z.object({
        channel: CHANNEL_KIND_ENUM,
        target: z.string().min(1).max(500),
    })).min(1).max(20),
});

/** Payload shape mirrors NotificationPayload — kept inline to avoid the cycle. */
const NotificationPayloadShapeSchema = z.object({
    type: NOTIF_TYPE_ENUM,
    severity: SEVERITY_ENUM,
    title: z.string().min(1).max(500),
    message: z.string().min(1).max(5000),
    data: z.record(z.unknown()).optional(),
});

/** POST /notifications/evaluate-rules and /notifications/dispatch */
export const EvaluateRulesSchema = z.object({
    rules: z.array(NotificationRuleSchema).min(1).max(100),
    payload: NotificationPayloadShapeSchema,
});
export type EvaluateRules = z.infer<typeof EvaluateRulesSchema>;

// ── Playbook route schemas ──────────────────────────────────────────

const PlaybookActionSchema = z.object({
    type: z.enum(['enrich', 'notify', 'alert', 'tag', 'warninglist_check', 'sandbox_trigger']),
    config: z.record(z.unknown()),
    // Phase 4 #3 — per-step guards. All optional; backwards-compatible with
    // legacy rows that omit them.
    if: z.record(z.unknown()).optional(),
    continueOnError: z.boolean().optional(),
    label: z.string().max(200).optional(),
});

/** POST /v1/playbooks — create a new playbook */
export const CreatePlaybookSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    description: z.string().max(2000).optional(),
    triggerEvent: z.string().min(1, 'triggerEvent is required').max(200),
    conditions: z.record(z.unknown()).optional(),
    actions: z.array(PlaybookActionSchema).min(1, 'At least one action is required'),
});
export type CreatePlaybook = z.infer<typeof CreatePlaybookSchema>;

/** PUT /v1/playbooks/:id — partial update */
export const UpdatePlaybookSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(2000).optional(),
    triggerEvent: z.string().min(1).max(200).optional(),
    conditions: z.record(z.unknown()).optional(),
    actions: z.array(PlaybookActionSchema).min(1).optional(),
    enabled: z.boolean().optional(),
});
export type UpdatePlaybook = z.infer<typeof UpdatePlaybookSchema>;

// ── Warninglist route schemas ───────────────────────────────────────

/** POST /v1/warninglists — create a new warninglist */
export const CreateWarninglistSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    type: z.enum(['cidr', 'hostname', 'string', 'regex']),
    description: z.string().max(2000).optional(),
    category: z.string().max(100).optional(),
    source: z.string().max(200).optional(),
    version: z.string().max(50).optional(),
    entries: z.array(z.string()).optional(),
});
export type CreateWarninglist = z.infer<typeof CreateWarninglistSchema>;

/** PUT /v1/warninglists/:id — partial update */
export const UpdateWarninglistSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(2000).optional(),
    category: z.string().max(100).optional(),
    source: z.string().max(200).optional(),
    version: z.string().max(50).optional(),
    enabled: z.boolean().optional(),
});
export type UpdateWarninglist = z.infer<typeof UpdateWarninglistSchema>;

/** POST/DELETE /v1/warninglists/:id/entries — add or remove entries */
export const WarninglistEntriesSchema = z.object({
    values: z.array(z.string()).min(1, 'At least one value is required'),
});
export type WarninglistEntries = z.infer<typeof WarninglistEntriesSchema>;

/** POST /v1/warninglists/check — check a value against warninglists */
export const WarninglistCheckSchema = z.object({
    value: z.string().min(1, 'value is required'),
    type: z.string().max(50).optional(),
});
export type WarninglistCheck = z.infer<typeof WarninglistCheckSchema>;

// ── YARA route schemas ──────────────────────────────────────────────

const YaraStringSchema = z.object({
    id: z.string(),
    value: z.string(),
    type: z.enum(['text', 'hex', 'regex']).default('text'),
    modifiers: z.array(z.string()).default([]),
});

/** POST /v1/yara/rules — add a YARA rule */
export const AddYaraRuleSchema = z.object({
    name: z.string().min(1, 'name is required').regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/, 'name must be alphanumeric with underscores'),
    description: z.string().max(2000).default(''),
    author: z.string().max(200).default('API'),
    tags: z.array(z.string()).default([]),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
    strings: z.array(YaraStringSchema).min(1, 'At least one string pattern is required'),
    condition: z.string().min(1, 'condition is required'),
    enabled: z.boolean().default(true),
});
export type AddYaraRule = z.infer<typeof AddYaraRuleSchema>;

/** PUT /v1/yara/rules/:name/toggle — toggle rule enabled/disabled */
export const ToggleYaraRuleSchema = z.object({
    enabled: z.boolean({ required_error: 'enabled is required' }),
});
export type ToggleYaraRule = z.infer<typeof ToggleYaraRuleSchema>;

/** POST /v1/yara/scan — scan a single value */
export const YaraScanSchema = z.object({
    value: z.string().min(1, 'value is required'),
});
export type YaraScan = z.infer<typeof YaraScanSchema>;

/** POST /v1/yara/batch-scan — scan multiple values */
export const YaraBatchScanSchema = z.object({
    values: z.array(z.string()).min(1, 'At least one value is required').max(10000, 'Maximum 10,000 values per batch'),
});
export type YaraBatchScan = z.infer<typeof YaraBatchScanSchema>;

// ── Sigma route schemas ──────────────────────────────────────────────

/** POST /v1/sigma/rules — ingest one or more Sigma YAML rules */
export const SigmaIngestSchema = z.object({
    yaml: z.string().min(1, 'yaml is required').max(5 * 1024 * 1024, 'YAML body exceeds 5 MiB'),
});
export type SigmaIngest = z.infer<typeof SigmaIngestSchema>;

/** POST /v1/sigma/import/url — fetch a Sigma YAML by URL and ingest */
export const SigmaImportUrlSchema = z.object({
    url: z.string().url('url must be http(s)://...'),
});
export type SigmaImportUrl = z.infer<typeof SigmaImportUrlSchema>;

/** GET /v1/sigma/rules — list filters */
export const SigmaListSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']).optional(),
    status: z.enum(['stable', 'test', 'experimental', 'deprecated', 'unsupported']).optional(),
    source: z.string().max(100).optional(),
    q: z.string().max(200).optional(),
    technique: z.string().max(20).optional(),
    tactic: z.string().max(50).optional(),
});
export type SigmaListFilters = z.infer<typeof SigmaListSchema>;

// ── Phase 4 #2 — SIEM exporters ────────────────────────────────────

/** POST /v1/export/{cef|leef|ecs} — IOC dump in vendor-neutral SIEM formats */
export const SiemExportSchema = z.object({
    dateFrom: z.string().max(40).optional(),
    dateTo: z.string().max(40).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    type: z.string().max(50).optional(),
    limit: z.coerce.number().int().min(1).max(100_000).default(10_000),
});
export type SiemExport = z.infer<typeof SiemExportSchema>;

/**
 * POST /v1/siem/push/{splunk|elastic} — same filter shape as the export
 * routes, plus optional per-request overrides for the target's index.
 * Cap pushes harder than downloads (5k vs 100k) — pushes happen on a
 * single API request and we'd rather force the operator to page than
 * burn 100k events on one timeout-prone fetch.
 */
export const SiemPushSchema = z.object({
    dateFrom: z.string().max(40).optional(),
    dateTo: z.string().max(40).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    type: z.string().max(50).optional(),
    limit: z.coerce.number().int().min(1).max(5_000).default(1_000),
    /** Vendor-specific overrides. Both clients fall back to env defaults. */
    index: z.string().max(255).optional(),
    sourcetype: z.string().max(100).optional(),
});
export type SiemPush = z.infer<typeof SiemPushSchema>;

/**
 * POST /v1/reports/ingest-text — Phase 3 #1 (Report ingestion scaffold).
 * Operator-pasted free-form text → deterministic IOCs + LLM-extracted
 * entities returned as a draft for review. Text cap matches the
 * service-side MAX_TEXT_LEN; the LLM helper internally truncates to 6k.
 */
export const ReportIngestTextSchema = z.object({
    text: z.string().min(1, 'text is required').max(200_000),
    source: z.string().max(2048).optional(),
    provider: z.enum(['gemini', 'openrouter', 'ollama']).optional(),
    skipLlm: z.boolean().optional(),
});
export type ReportIngestText = z.infer<typeof ReportIngestTextSchema>;

/**
 * POST /v1/reports/ingest-url — fetch + readability-extract a URL, then
 * run the same downstream pipeline as /ingest-text. Only http/https
 * accepted; the service-side fetch enforces a 15 s timeout and 5 MB
 * body cap.
 */
export const ReportIngestUrlSchema = z.object({
    url: z.string().url().max(2048),
    source: z.string().max(2048).optional(),
    provider: z.enum(['gemini', 'openrouter', 'ollama']).optional(),
    skipLlm: z.boolean().optional(),
});
export type ReportIngestUrl = z.infer<typeof ReportIngestUrlSchema>;

/**
 * POST /v1/reports/:id/commit — apply operator-approved IOCs from a draft
 * to the canonical `iocs` table. `approvedIocs` is the subset the operator
 * actually wants imported; anything in the draft but not in this list is
 * skipped (with a `not_in_draft` counter in the response summary).
 *
 * Entity commit (threat-actor / malware family / etc.) is a separate
 * follow-on; this PR only commits IOCs.
 */
const IocKindEnum = z.enum([
    'ipv4', 'ipv6', 'domain', 'url', 'hash-md5', 'hash-sha1', 'hash-sha256', 'email', 'cve',
]);

export const ReportCommitSchema = z.object({
    approvedIocs: z.array(z.object({
        kind: IocKindEnum,
        value: z.string().min(1).max(2048),
    })).max(10_000).default([]),
    iocSource: z.string().max(255).optional(),
});
export type ReportCommit = z.infer<typeof ReportCommitSchema>;

/** GET /v1/reports — list filters for the draft browser. */
export const ReportListSchema = z.object({
    status: z.enum(['draft', 'committed', 'dismissed']).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type ReportList = z.infer<typeof ReportListSchema>;

// ── Phase 3 #5 — Hypothesis tracking ──────────────────────────────

const HypothesisSubjectTypeEnum = z.enum([
    'threat_actor', 'malware', 'campaign', 'infrastructure', 'ioc', 'cve',
]);

/** POST /v1/hypotheses — create */
export const HypothesisCreateSchema = z.object({
    title: z.string().min(1).max(500),
    claim: z.string().min(1).max(10_000),
    subjectType: HypothesisSubjectTypeEnum.optional(),
    subjectId: z.string().uuid().optional(),
    /** Initial confidence; defaults to 50. */
    confidenceScore: z.number().int().min(0).max(100).default(50),
}).refine(v => (v.subjectType ? !!v.subjectId : true), {
    message: 'subjectId is required when subjectType is set',
    path: ['subjectId'],
}).refine(v => (v.subjectId ? !!v.subjectType : true), {
    message: 'subjectType is required when subjectId is set',
    path: ['subjectType'],
});
export type HypothesisCreate = z.infer<typeof HypothesisCreateSchema>;

/** GET /v1/hypotheses — list filters */
export const HypothesisListSchema = z.object({
    status: z.enum(['active', 'confirmed', 'refuted']).optional(),
    subjectType: HypothesisSubjectTypeEnum.optional(),
    subjectId: z.string().uuid().optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type HypothesisList = z.infer<typeof HypothesisListSchema>;

/** PATCH /v1/hypotheses/:id — operator lifecycle update */
export const HypothesisUpdateSchema = z.object({
    status: z.enum(['active', 'confirmed', 'refuted']).optional(),
    title: z.string().min(1).max(500).optional(),
    claim: z.string().min(1).max(10_000).optional(),
});
export type HypothesisUpdate = z.infer<typeof HypothesisUpdateSchema>;

/** POST /v1/hypotheses/:id/evidence — append evidence */
export const EvidenceAppendSchema = z.object({
    evidenceType: z.enum([
        'ioc', 'relationship', 'sighting', 'actor', 'malware',
        'campaign', 'report', 'freeform',
    ]),
    entityId: z.string().max(255).optional(),
    kind: z.enum(['supports', 'refutes']),
    weight: z.number().int().min(0).max(100).default(50),
    note: z.string().max(2000).optional(),
}).refine(v => (v.evidenceType === 'freeform' ? !!v.note : true), {
    message: 'freeform evidence requires a note',
    path: ['note'],
}).refine(v => (v.evidenceType !== 'freeform' ? !!v.entityId : true), {
    message: 'entityId is required for non-freeform evidence',
    path: ['entityId'],
});
export type EvidenceAppend = z.infer<typeof EvidenceAppendSchema>;

/** POST /v1/hypotheses/:id/grade — LLM grading */
export const HypothesisGradeSchema = z.object({
    provider: z.enum(['gemini', 'openrouter', 'ollama']).optional(),
    skipLlm: z.boolean().optional(),
    /** When true, persist the new confidence + reasoning to the row. Defaults true. */
    persist: z.boolean().optional(),
});
export type HypothesisGrade = z.infer<typeof HypothesisGradeSchema>;

// ── Phase 5 #1 — Brand / typo-squat monitoring ────────────────────

/**
 * Apex domains the operator wants the scheduled sweep to watch. The
 * apex is normalised to lowercase + trimmed before storage; routes
 * downstream rely on that being the canonical form.
 */
export const MonitoredDomainCreateSchema = z.object({
    apexDomain: z.string()
        .min(3).max(255)
        .regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,24})+$/i, 'must be a valid apex domain (label.tld)')
        .transform(v => v.toLowerCase().trim()),
    label: z.string().max(255).optional(),
    owner: z.string().max(255).optional(),
    enabled: z.boolean().default(true),
});
export type MonitoredDomainCreate = z.infer<typeof MonitoredDomainCreateSchema>;

export const MonitoredDomainUpdateSchema = z.object({
    label: z.string().max(255).optional(),
    owner: z.string().max(255).optional(),
    enabled: z.boolean().optional(),
});
export type MonitoredDomainUpdate = z.infer<typeof MonitoredDomainUpdateSchema>;

/** GET /v1/brand/alerts — list filters for the triage queue. */
export const BrandAlertListSchema = z.object({
    monitoredDomainId: z.string().uuid().optional(),
    status: z.enum(['new', 'triaging', 'escalated', 'benign', 'blocked']).optional(),
    dnsState: z.enum(['active', 'mx_only', 'nx', 'error']).optional(),
    minScore: z.coerce.number().int().min(0).max(100).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type BrandAlertList = z.infer<typeof BrandAlertListSchema>;

/** PATCH /v1/brand/alerts/:id — analyst triage. */
export const BrandAlertUpdateSchema = z.object({
    status: z.enum(['new', 'triaging', 'escalated', 'benign', 'blocked']).optional(),
    notes: z.string().max(4000).optional(),
});
export type BrandAlertUpdate = z.infer<typeof BrandAlertUpdateSchema>;

// ── Phase 5 #2 — Threat-actor TTP changelog ────────────────────────

/** GET /v1/ttp-changes — filter the global change log. */
export const TtpChangeListSchema = z.object({
    actorId: z.string().max(128).optional(),
    techniqueId: z.string().max(128).optional(),
    changeType: z.enum(['added', 'removed']).optional(),
    /** ISO-8601 cutoff (e.g. `2026-05-09T00:00:00Z`); only entries `detected_at >= since` returned. */
    since: z.string().datetime().optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(500).default(100),
});
export type TtpChangeList = z.infer<typeof TtpChangeListSchema>;

// ── Phase 5 #3 — HIBP breach catalog ──────────────────────────────

/**
 * GET /v1/data-breaches — filter the breach catalog. Useful patterns:
 *   - ?domain=example.com           breaches at a specific domain
 *   - ?addedSince=2026-05-09T...    new breaches in the last 30 days
 *   - ?includeRetired=false         drop retired entries (default)
 *   - ?includeSpamList=false        drop spam-list entries (default)
 */
export const DataBreachListSchema = z.object({
    domain: z.string().max(255).optional(),
    name: z.string().max(255).optional(),
    addedSince: z.string().datetime().optional(),
    breachSince: z.string().datetime().optional(),
    includeRetired: z.coerce.boolean().default(false),
    includeSpamList: z.coerce.boolean().default(false),
    includeFabricated: z.coerce.boolean().default(false),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(500).default(100),
});
export type DataBreachList = z.infer<typeof DataBreachListSchema>;

// ── Phase 5 #4 — Dark-web monitoring (Ahmia) ──────────────────────

/** POST /v1/dark-web/watchterms — add a search term. */
export const DarkWebWatchtermCreateSchema = z.object({
    term: z.string().min(1).max(255),
    kind: z.string().max(50).optional(),
    owner: z.string().max(255).optional(),
    enabled: z.boolean().default(true),
});
export type DarkWebWatchtermCreate = z.infer<typeof DarkWebWatchtermCreateSchema>;

export const DarkWebWatchtermUpdateSchema = z.object({
    kind: z.string().max(50).optional(),
    owner: z.string().max(255).optional(),
    enabled: z.boolean().optional(),
});
export type DarkWebWatchtermUpdate = z.infer<typeof DarkWebWatchtermUpdateSchema>;

/** GET /v1/dark-web/mentions — triage queue filter. */
export const DarkWebMentionListSchema = z.object({
    watchtermId: z.string().uuid().optional(),
    status: z.enum(['new', 'triaging', 'escalated', 'benign', 'blocked']).optional(),
    minScore: z.coerce.number().int().min(0).max(100).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type DarkWebMentionList = z.infer<typeof DarkWebMentionListSchema>;

export const DarkWebMentionUpdateSchema = z.object({
    status: z.enum(['new', 'triaging', 'escalated', 'benign', 'blocked']).optional(),
    notes: z.string().max(4000).optional(),
});
export type DarkWebMentionUpdate = z.infer<typeof DarkWebMentionUpdateSchema>;

// ── Phase 5 #5 — Paste-site monitoring (GitHub Gist firehose) ─────

export const PasteWatchtermCreateSchema = z.object({
    term: z.string().min(1).max(255),
    kind: z.string().max(50).optional(),
    owner: z.string().max(255).optional(),
    enabled: z.boolean().default(true),
});
export type PasteWatchtermCreate = z.infer<typeof PasteWatchtermCreateSchema>;

export const PasteWatchtermUpdateSchema = z.object({
    kind: z.string().max(50).optional(),
    owner: z.string().max(255).optional(),
    enabled: z.boolean().optional(),
});
export type PasteWatchtermUpdate = z.infer<typeof PasteWatchtermUpdateSchema>;

export const PasteMentionListSchema = z.object({
    watchtermId: z.string().uuid().optional(),
    status: z.enum(['new', 'triaging', 'escalated', 'benign', 'blocked']).optional(),
    minScore: z.coerce.number().int().min(0).max(100).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type PasteMentionList = z.infer<typeof PasteMentionListSchema>;

export const PasteMentionUpdateSchema = z.object({
    status: z.enum(['new', 'triaging', 'escalated', 'benign', 'blocked']).optional(),
    notes: z.string().max(4000).optional(),
});
export type PasteMentionUpdate = z.infer<typeof PasteMentionUpdateSchema>;

// ── Phase 4 #4 — Blocklist feed query params ───────────────────────

/** GET /v1/feeds/blocklist/:vendor/:type — vendor firewall feed */
export const BlocklistFeedSchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    limit: z.coerce.number().int().min(1).max(100_000).default(10_000),
});
export type BlocklistFeed = z.infer<typeof BlocklistFeedSchema>;

// ── Phase 4 #5 — Sandbox submissions ───────────────────────────────

const SANDBOX_VENDORS = ['anyrun', 'joesandbox', 'hybridanalysis'] as const;
const SANDBOX_SUBMIT_TYPES = ['url', 'hash', 'file', 'ioc'] as const;
const SANDBOX_STATUS = ['queued', 'running', 'completed', 'failed', 'timeout'] as const;

/** POST /v1/sandbox/submit — kick off a sandbox analysis */
export const SandboxSubmitSchema = z.object({
    vendor: z.enum(SANDBOX_VENDORS),
    value: z.string().min(1, 'value is required').max(2048),
    type: z.enum(SANDBOX_SUBMIT_TYPES),
    iocId: z.string().uuid('iocId must be a UUID').optional(),
    options: z.record(z.unknown()).optional(),
});
export type SandboxSubmit = z.infer<typeof SandboxSubmitSchema>;

/** GET /v1/sandbox/reports — list filters */
export const SandboxListFiltersSchema = z.object({
    vendor: z.enum(SANDBOX_VENDORS).optional(),
    status: z.enum(SANDBOX_STATUS).optional(),
    iocId: z.string().uuid().optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type SandboxListFilters = z.infer<typeof SandboxListFiltersSchema>;

// ── Phase 4 #6 — Ticketing (GitHub Issues scaffold) ────────────────

const TICKET_VENDORS = ['github', 'jira'] as const;

/** POST /v1/cases/:caseId/tickets — link or open an external ticket for a case */
export const TicketCreateSchema = z.object({
    vendor: z.enum(TICKET_VENDORS),
    /** github: "owner/repo". jira: project key. */
    repo: z.string().min(1, 'repo is required').max(255),
    title: z.string().min(1).max(256).optional(),
    body: z.string().max(65536).optional(),
    labels: z.array(z.string().max(100)).max(50).optional(),
});
export type TicketCreate = z.infer<typeof TicketCreateSchema>;

/** POST /v1/tickets/:linkId/comment — push a comment to the external ticket */
export const TicketCommentSchema = z.object({
    body: z.string().min(1, 'body is required').max(65536),
});
export type TicketComment = z.infer<typeof TicketCommentSchema>;

/** GET /v1/tickets — list filters */
export const TicketListFiltersSchema = z.object({
    caseId: z.string().max(255).optional(),
    vendor: z.enum(TICKET_VENDORS).optional(),
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(200).default(50),
});
export type TicketListFilters = z.infer<typeof TicketListFiltersSchema>;

// ── Phase 3 #2 — Actor activity summary ────────────────────────────

/** GET|POST /v1/threat-actors/:id/summary — LLM-backed activity briefing */
export const ActorSummarySchema = z.object({
    days: z.coerce.number().int().min(1).max(365).default(30),
    context: z.string().max(200).optional(),
    provider: z.enum(['gemini', 'openrouter', 'ollama']).optional(),
});
export type ActorSummary = z.infer<typeof ActorSummarySchema>;

// ── Phase 3 #4 — NL → Cypher ───────────────────────────────────────

/** POST /v1/graph/nl-query — natural-language question → Cypher → records */
export const NlCypherSchema = z.object({
    question: z.string().min(1, 'question is required').max(2000),
    limit: z.coerce.number().int().min(1).max(500).default(25),
    provider: z.enum(['gemini', 'openrouter', 'ollama']).optional(),
});
export type NlCypher = z.infer<typeof NlCypherSchema>;

// ── TAXII push targets ──────────────────────────────────────────────

/** POST /v1/taxii/remote-targets — register a new outbound TAXII target */
export const TaxiiRemoteTargetCreateSchema = z.object({
    name: z.string().min(1, 'name is required').max(255),
    discoveryUrl: z.string().url('discoveryUrl must be http(s)://...'),
    apiRoot: z.string().url('apiRoot must be http(s)://...'),
    collectionId: z.string().min(1, 'collectionId is required').max(255),
    apiKeyRef: z.string().max(255).optional(),
    enabled: z.boolean().default(true),
    pushFilter: z.object({
        iocType: z.string().max(50).optional(),
        iocSource: z.string().max(100).optional(),
        severity: z.string().max(20).optional(),
        iocLimit: z.number().int().min(1).max(50_000).optional(),
        threatActorLimit: z.number().int().min(0).max(10_000).optional(),
        vulnerabilityLimit: z.number().int().min(0).max(50_000).optional(),
        defaultTlp: z.enum(['white', 'green', 'amber', 'red']).optional(),
        includeIOCs: z.boolean().optional(),
        includeThreatActors: z.boolean().optional(),
        includeVulnerabilities: z.boolean().optional(),
    }).default({}),
});
export type TaxiiRemoteTargetCreate = z.infer<typeof TaxiiRemoteTargetCreateSchema>;

/** PUT /v1/taxii/remote-targets/:id — partial update */
export const TaxiiRemoteTargetUpdateSchema = TaxiiRemoteTargetCreateSchema.partial();
export type TaxiiRemoteTargetUpdate = z.infer<typeof TaxiiRemoteTargetUpdateSchema>;

// ── Playbook execute schema ─────────────────────────────────────────

/** POST /v1/playbooks/:id/execute — manually trigger execution */
export const ExecutePlaybookSchema = z.object({
    triggerData: z.record(z.unknown()).default({}),
});
export type ExecutePlaybook = z.infer<typeof ExecutePlaybookSchema>;

// ── STIX Pipeline schemas ───────────────────────────────────────────

const StixObjectSchema = z.object({
    type: z.string().min(1),
    id: z.string().min(1),
}).passthrough();

/** POST /v1/stix/import — import a STIX 2.1 bundle */
export const StixImportSchema = z.object({
    type: z.literal('bundle'),
    id: z.string().min(1, 'bundle id is required'),
    objects: z.array(StixObjectSchema).max(10000, 'Bundle too large: max 10,000 objects'),
    dryRun: z.boolean().default(false),
}).passthrough();
export type StixImport = z.infer<typeof StixImportSchema>;

/** POST /v1/stix/export — export entities as STIX 2.1 */
export const StixExportSchema = z.object({
    entityTypes: z.array(z.string()).default(['iocs']),
    includeRelationships: z.boolean().default(true),
    limit: z.number().int().min(1).max(5000).default(1000),
});
export type StixExport = z.infer<typeof StixExportSchema>;

// ── User schemas ────────────────────────────────────────────────────

/** POST /users — create a new user */
export const CreateUserSchema = z.object({
    email: z.string().email('Valid email is required'),
    name: z.string().min(1, 'name is required').max(200),
    role: z.enum(['admin', 'analyst', 'viewer']),
});
export type CreateUser = z.infer<typeof CreateUserSchema>;

/** PUT /users/:id — update a user */
export const UpdateUserSchema = z.object({
    email: z.string().email().optional(),
    name: z.string().min(1).max(200).optional(),
    role: z.enum(['admin', 'analyst', 'viewer']).optional(),
    status: z.enum(['active', 'inactive', 'pending']).optional(),
});
export type UpdateUser = z.infer<typeof UpdateUserSchema>;

// ── Sighting schema ─────────────────────────────────────────────────

/** POST /v1/iocs/:iocId/sightings — report a sighting */
export const AddSightingSchema = z.object({
    source: z.string().min(1, 'source is required').max(200),
    type: z.enum(['sighting', 'false-positive', 'expiration']).optional(),
    description: z.string().max(2000).optional(),
    confidence: z.number().min(0).max(100).optional(),
    count: z.number().int().min(1).optional(),
    observedAt: z.string().datetime().optional(),
});
export type AddSighting = z.infer<typeof AddSightingSchema>;

// ── Config update schemas ───────────────────────────────────────────

/** PUT /config/api-keys/:id — update API key value */
export const UpdateApiKeyValueSchema = z.object({
    value: z.string().min(1, 'API key value is required'),
});
export type UpdateApiKeyValue = z.infer<typeof UpdateApiKeyValueSchema>;

/** PUT /config/services/:id — update service env vars */
export const UpdateServiceSchema = z.object({}).passthrough();
export type UpdateService = z.infer<typeof UpdateServiceSchema>;

/** PUT /config/feeds/:id — update a feed */
export const UpdateFeedSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    source: z.string().max(200).optional(),
    description: z.string().max(1000).optional(),
    cron: z.string().max(50).optional(),
    enabled: z.boolean().optional(),
    category: z.string().max(100).optional(),
    url: z.string().url().optional(),
    format: z.enum(['json', 'text', 'rss', 'csv', 'stix']).optional(),
    authHeader: z.string().max(200).optional(),
    authKeyRef: z.string().max(200).optional(),
});
export type UpdateFeed = z.infer<typeof UpdateFeedSchema>;

// ============================================================================
// Phase T — Graph, Export, TAXII, Enrich, Streaming Schemas
// ============================================================================

/** POST /v1/graph/neo4j/sync — Trigger a Neo4j sync job */
export const Neo4jSyncSchema = z.object({
    syncType: z.enum(['full', 'incremental', 'iocs', 'all-iocs', 'actors', 'cves', 'techniques', 'malware', 'tools', 'relationships', 'telco', 'onchain', 'frameworks', 'pulses-iocs', 'similarity']).default('full'),
    options: z.record(z.unknown()).default({}),
});
export type Neo4jSync = z.infer<typeof Neo4jSyncSchema>;

/** POST /v1/graph/neo4j/cypher — Execute a read-only Cypher query */
export const CypherQuerySchema = z.object({
    query: z.string().min(1, 'query is required').max(5000),
    params: z.record(z.unknown()).optional(),
    limit: z.number().int().min(1).max(1000).default(100),
});
export type CypherQuery = z.infer<typeof CypherQuerySchema>;

/** Shared schema for all export POST routes (csv, json, stix) */
export const ExportRequestSchema = z.object({
    filters: z.record(z.unknown()).default({}),
    limit: z.number().int().min(1).max(50000).default(10000),
});
export type ExportRequest = z.infer<typeof ExportRequestSchema>;

/** POST /taxii2/collections/:id/objects/ — Inbound STIX bundle ingestion */
export const TaxiiInboundSchema = z.object({
    type: z.literal('bundle', { errorMap: () => ({ message: 'Request body must be a valid STIX 2.1 bundle' }) }),
    objects: z.array(z.record(z.unknown())).max(10000, 'Bundle exceeds maximum 10,000 objects'),
}).passthrough();
export type TaxiiInbound = z.infer<typeof TaxiiInboundSchema>;

/** POST /v1/enrich/bulk — Bulk enrichment for multiple IOCs */
export const BulkEnrichSchema = z.object({
    values: z.array(z.string()).min(1, 'Values array is required').max(100, 'Maximum 100 values per request'),
});
export type BulkEnrich = z.infer<typeof BulkEnrichSchema>;

/** POST /v2/stream/subscribe — Create a filtered subscription */
export const StreamSubscribeSchema = z.object({
    channels: z.array(z.string()).default(['webint']),
    keywords: z.array(z.string()).default([]),
});
export type StreamSubscribe = z.infer<typeof StreamSubscribeSchema>;

// ============================================================================
// Phase W — Opengate, Webhooks, Admin Users/Jobs/Sandbox Schemas
// ============================================================================

/** POST /opengate/keys — Create an API key */
export const CreateApiKeySchema = z.object({
    name: z.string().min(1).max(100).default('API Key'),
});
export type CreateApiKey = z.infer<typeof CreateApiKeySchema>;

/** POST /v1/webhooks — Register a webhook subscription */
export const CreateWebhookSchema = z.object({
    name: z.string().min(1, 'name is required').max(200),
    url: z.string().url('Invalid URL format'),
    secret: z.string().optional(),
    events: z.array(z.string()).default(['*']),
    filters: z.object({
        severity: z.array(z.string()).optional(),
        type: z.array(z.string()).optional(),
        source: z.array(z.string()).optional(),
    }).default({}),
    headers: z.record(z.string()).default({}),
});
export type CreateWebhook = z.infer<typeof CreateWebhookSchema>;

/** POST /admin/users — Create a user */
export const AdminCreateUserSchema = z.object({
    email: z.string().email('Valid email is required'),
    name: z.string().min(1, 'name is required').max(200),
    role: z.string().min(1, 'role is required'),
    permissions: z.array(z.string()).optional(),
    avatarUrl: z.string().max(500000).nullable().optional(),
});
export type AdminCreateUser = z.infer<typeof AdminCreateUserSchema>;

/** PUT /admin/users/:id — Update a user */
export const AdminUpdateUserSchema = z.object({
    email: z.string().email().optional(),
    name: z.string().min(1).max(200).optional(),
    role: z.string().min(1).optional(),
    permissions: z.array(z.string()).optional(),
    isActive: z.boolean().optional(),
    avatarUrl: z.string().max(500000).nullable().optional(),
});
export type AdminUpdateUser = z.infer<typeof AdminUpdateUserSchema>;

/** POST /admin/users/:id/change-password — Change user password */
export const ChangePasswordSchema = z.object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: z.string().min(8, 'Password must be at least 8 characters').max(128),
});
export type ChangePassword = z.infer<typeof ChangePasswordSchema>;

/** POST /admin/users/roles — Create a role */
export const AdminCreateRoleSchema = z.object({
    id: z.string().min(1, 'id is required').max(50),
    name: z.string().min(1, 'name is required').max(200),
    description: z.string().default(''),
    defaultPermissions: z.array(z.string()).default([]),
});
export type AdminCreateRole = z.infer<typeof AdminCreateRoleSchema>;

/** PUT /admin/users/roles/:id — Update a role */
export const AdminUpdateRoleSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().optional(),
    defaultPermissions: z.array(z.string()).optional(),
});
export type AdminUpdateRole = z.infer<typeof AdminUpdateRoleSchema>;

/** POST /admin/users/permissions — Create a permission module */
export const AdminCreatePermModuleSchema = z.object({
    id: z.string().min(1, 'id is required').max(50),
    name: z.string().min(1, 'name is required').max(200),
    icon: z.string().default('settings'),
    permissions: z.array(z.object({
        id: z.string().min(1),
        name: z.string().min(1),
        description: z.string(),
    })).default([]),
});
export type AdminCreatePermModule = z.infer<typeof AdminCreatePermModuleSchema>;

/** PUT /admin/users/permissions/:id — Update a permission module */
export const AdminUpdatePermModuleSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    icon: z.string().optional(),
    permissions: z.array(z.object({
        id: z.string().min(1),
        name: z.string().min(1),
        description: z.string(),
    })).optional(),
});
export type AdminUpdatePermModule = z.infer<typeof AdminUpdatePermModuleSchema>;

/** POST /admin/jobs/feed-sync — Trigger a feed sync job */
export const FeedSyncJobSchema = z.object({
    source: z.string().default('all'),
    options: z.record(z.unknown()).optional(),
});
export type FeedSyncJob = z.infer<typeof FeedSyncJobSchema>;

/** POST /admin/jobs/enrichment — Queue IOC enrichment */
export const EnrichmentJobSchema = z.object({
    iocId: z.string().min(1, 'iocId is required'),
    iocValue: z.string().min(1, 'iocValue is required'),
    iocType: z.string().min(1, 'iocType is required'),
    sources: z.array(z.string()).optional(),
});
export type EnrichmentJob = z.infer<typeof EnrichmentJobSchema>;

/** POST /admin/jobs/ai-analysis — Queue AI analysis */
export const AiAnalysisJobSchema = z.object({
    iocId: z.string().min(1, 'iocId is required'),
    iocValue: z.string().min(1, 'iocValue is required'),
    analysisType: z.string().default('threat-assessment'),
});
export type AiAnalysisJob = z.infer<typeof AiAnalysisJobSchema>;

/** POST /admin/jobs/notification — Queue a notification */
export const NotificationJobQueueSchema = z.object({
    channel: z.string().min(1, 'channel is required'),
    target: z.string().min(1, 'target is required'),
    payload: z.record(z.unknown()),
});
export type NotificationJobQueue = z.infer<typeof NotificationJobQueueSchema>;

/** POST /admin/jobs/neo4j-sync — Trigger Neo4j sync */
export const Neo4jSyncJobSchema = z.object({
    syncType: z.string().default('all-iocs'),
    options: z.record(z.unknown()).optional(),
});
export type Neo4jSyncJob = z.infer<typeof Neo4jSyncJobSchema>;

/** POST /admin/sandbox/test-feed — Test feed connectivity */
export const SandboxTestFeedSchema = z.object({
    url: z.string().url('Invalid URL format'),
    authHeader: z.string().optional(),
    authValue: z.string().optional(),
    authType: z.enum(['header', 'query']).optional(),
    authParam: z.string().optional(),
    method: z.enum(['GET', 'POST', 'HEAD', 'get', 'post', 'head']).default('GET'),
});
export type SandboxTestFeed = z.infer<typeof SandboxTestFeedSchema>;

/** POST /admin/sandbox/test-endpoint — Test arbitrary endpoint */
export const SandboxTestEndpointSchema = z.object({
    url: z.string().url('Invalid URL format'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD',
        'get', 'post', 'put', 'delete', 'patch', 'head']).default('GET'),
    headers: z.record(z.string()).optional(),
    body: z.unknown().optional(),
    timeoutMs: z.number().int().min(1000).max(30000).default(10000),
});
export type SandboxTestEndpoint = z.infer<typeof SandboxTestEndpointSchema>;

// ============================================================================
// Phase Y — Remaining Route Validation Schemas
// ============================================================================

/** POST /v1/correlation/batch — batch correlation limit */
export const BatchCorrelationSchema = z.object({
    limit: z.coerce.number().int().min(1).max(5000).default(500),
});
export type BatchCorrelation = z.infer<typeof BatchCorrelationSchema>;

/** GET /v1/iocs/:iocId/sightings — list sightings */
export const SightingListSchema = z.object({
    limit: z.coerce.number().int().min(1).max(500).default(50),
    offset: z.coerce.number().int().min(0).default(0),
});
export type SightingList = z.infer<typeof SightingListSchema>;

/** GET /v1/sightings/feed — sighting feed with optional iocId filter */
export const SightingFeedSchema = z.object({
    limit: z.coerce.number().int().min(1).max(500).default(50),
    iocId: z.string().optional(),
});
export type SightingFeed = z.infer<typeof SightingFeedSchema>;

/** GET /v1/alerts — alert list filters */
export const AlertListFilterSchema = PaginationSchema.extend({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    unread: z.coerce.boolean().optional(),
    // Durable-store faceting (additive — older clients omit these).
    read: z.coerce.boolean().optional(),
    source: z.string().max(120).optional(),
    type: z.string().max(60).optional(),
});
export type AlertListFilter = z.infer<typeof AlertListFilterSchema>;

/** GET /v1/audit — audit log filters */
export const AuditFilterSchema = LimitOffsetSchema.extend({
    entityType: z.string().optional(),
    entityId: z.string().optional(),
    action: z.string().optional(),
    source: z.string().optional(),
});
export type AuditFilter = z.infer<typeof AuditFilterSchema>;

/** GET /v2/stix/bundle — STIX bundle export filters */
export const StixBundleQuerySchema = LimitSchema.extend({
    include: z.string().optional(),
    type: z.string().optional(),
    source: z.string().optional(),
    severity: z.string().optional(),
});
export type StixBundleQuery = z.infer<typeof StixBundleQuerySchema>;

/** GET /taxii2/collections/:id/objects/ — TAXII envelope query */
export const TaxiiEnvelopeQuerySchema = z.object({
    added_after: z.string().optional(),
    limit: z.coerce.number().int().min(1).max(1000).default(100),
    next: z.string().optional(),
    'match[type]': z.string().optional(),
    'match[id]': z.string().optional(),
});
export type TaxiiEnvelopeQuery = z.infer<typeof TaxiiEnvelopeQuerySchema>;

/** GET /intelligence/ioc/:value — intelligence query params */
export const IntelligenceIOCQuerySchema = z.object({
    refresh: z.coerce.boolean().default(false),
    sources: z.string().optional(),
});
export type IntelligenceIOCQuery = z.infer<typeof IntelligenceIOCQuerySchema>;

// ============================================================================
// Phase Z — Final Validation Sweep Schemas
// ============================================================================

/**
 * GET /admin/audit — paginated, filterable audit log list.
 *
 * `entityType` and `action` derive from the Drizzle pgEnums so the Zod
 * validator, the audit service, and the DB enum can never silently drift
 * apart (which previously caused user-audit writes to fail at insert time).
 */
export const AdminAuditListSchema = z.object({
    entityType: z.enum(entityTypeEnum.enumValues).optional(),
    action: z.enum(auditActionEnum.enumValues).optional(),
    from: z.string().optional(),
    to: z.string().optional(),
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(50),
});
export type AdminAuditList = z.infer<typeof AdminAuditListSchema>;

/** GET /admin/audit/stats — audit stats time range */
export const AdminAuditStatsSchema = z.object({
    days: z.coerce.number().int().min(1).max(365).default(30),
});
export type AdminAuditStats = z.infer<typeof AdminAuditStatsSchema>;

/** GET /admin/users — filterable user list */
export const AdminUserListSchema = z.object({
    role: z.string().optional(),
    status: z.enum(['active', 'inactive', 'all']).optional(),
    search: z.string().optional(),
    page: z.coerce.number().int().min(1).optional(),
    limit: z.coerce.number().int().min(1).max(100).optional(),
});
export type AdminUserList = z.infer<typeof AdminUserListSchema>;

/** POST /admin/queue/:name/clean/:state — queue clean params */
export const AdminQueueCleanSchema = z.object({
    grace: z.coerce.number().int().min(0).default(0),
    limit: z.coerce.number().int().min(1).max(10000).default(1000),
});
export type AdminQueueClean = z.infer<typeof AdminQueueCleanSchema>;

/** GET /admin/queue/:name/jobs — queue job listing params */
export const AdminQueueJobsSchema = z.object({
    state: z.enum(['waiting', 'active', 'completed', 'failed', 'delayed']).default('failed'),
    start: z.coerce.number().int().min(0).default(0),
    limit: z.coerce.number().int().min(1).max(500).default(20),
});
export type AdminQueueJobs = z.infer<typeof AdminQueueJobsSchema>;

/** GET /admin/dlq — DLQ pagination */
export const AdminDLQListSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(50),
});
export type AdminDLQList = z.infer<typeof AdminDLQListSchema>;

/** POST /admin/streams/:stream/claim — stream claim query params */
export const AdminStreamClaimSchema = z.object({
    group: z.string().default('enrichment-group'),
    consumer: z.string().default('claimer'),
    minIdleMs: z.coerce.number().int().min(0).default(60000),
});
export type AdminStreamClaim = z.infer<typeof AdminStreamClaimSchema>;

/** GET /users — in-memory user list filters */
export const UserListQuerySchema = z.object({
    status: z.string().optional(),
    role: z.string().optional(),
});
export type UserListQuery = z.infer<typeof UserListQuerySchema>;

/** GET /export/iocs — bulk export format */
export const BulkExportQuerySchema = z.object({
    format: z.enum(['json', 'csv', 'stix']).default('json'),
});
export type BulkExportQuery = z.infer<typeof BulkExportQuerySchema>;

/** GET /monitoring/metrics/growth — granularity param */
export const MetricsGrowthQuerySchema = z.object({
    granularity: z.enum(['day', 'hour']).default('day'),
});
export type MetricsGrowthQuery = z.infer<typeof MetricsGrowthQuerySchema>;

// ============================================================================
// Phase AA — AI Analysis Body Schema
// ============================================================================

/** POST /v2/ai/analyze — AI entity analysis request body */
export const AIAnalyzeSchema = z.object({
    entityType: z.enum(['ioc', 'cve', 'actor']),
    entityId: z.string().min(1, 'entityId is required'),
    entityData: z.record(z.unknown()),
    forceRefresh: z.boolean().default(false),
});
export type AIAnalyze = z.infer<typeof AIAnalyzeSchema>;

/** POST /v2/events/publish — SSE event publish body */
export const SSEPublishSchema = z.object({
    channel: z.enum(['ioc', 'alert', 'feed', 'enrichment', 'system']),
    type: z.string().min(1, 'type is required'),
    data: z.record(z.unknown()),
    source: z.string().optional(),
});
export type SSEPublish = z.infer<typeof SSEPublishSchema>;

// ============================================================================
// Phase AC — Feed Management Enhancements (MISP/IntelOwl inspired)
// ============================================================================

/** POST /v1/config/feeds/:id/sync — Trigger manual feed sync */
export const FeedSyncTriggerSchema = z.object({
    force: z.boolean().default(false),
});
export type FeedSyncTrigger = z.infer<typeof FeedSyncTriggerSchema>;

/** GET /v1/config/feeds/:id/history — Feed sync run history */
export const FeedSyncHistoryQuerySchema = z.object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
});
export type FeedSyncHistoryQuery = z.infer<typeof FeedSyncHistoryQuerySchema>;

// ============================================================================
// Phase AD — Indicator Lifecycle Management (MISP/STIX 2.1 inspired)
// ============================================================================

/** POST /v1/iocs — Single manual IOC create */
export const IOCCreateSchema = z.object({
    type: z.enum(['ip', 'ipv6', 'domain', 'url', 'hash-md5', 'hash-sha1', 'hash-sha256', 'email', 'hostname', 'cve', 'mutex', 'filename', 'registry']),
    value: z.string().min(1, 'value is required').max(2048),
    source: z.string().min(1, 'source is required').max(100),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    confidence: z.number().int().min(0).max(100).optional(),
    tags: z.array(z.string().max(64)).max(50).optional(),
    threatType: z.string().max(200).optional(),
    notes: z.string().max(5000).optional(),
});
export type IOCCreate = z.infer<typeof IOCCreateSchema>;

/** PUT /v1/iocs/:id — Partial update of IOC fields */
export const IOCUpdateSchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    confidence: z.number().int().min(0).max(100).optional(),
    tags: z.array(z.string()).optional(),
    threatType: z.string().max(200).optional(),
    notes: z.string().max(5000).optional(),
}).refine(obj => Object.keys(obj).length > 0, 'At least one field must be specified');
export type IOCUpdate = z.infer<typeof IOCUpdateSchema>;

/** POST /v1/iocs/:id/revoke — Mark IOC as revoked (soft-delete) */
export const IOCRevokeSchema = z.object({
    reason: z.string().min(1, 'reason is required').max(2000),
});
export type IOCRevoke = z.infer<typeof IOCRevokeSchema>;

/** POST /v1/iocs/:id/expire — Set valid_until date */
export const IOCExpireSchema = z.object({
    validUntil: z.string().datetime('Must be a valid ISO datetime'),
});
export type IOCExpire = z.infer<typeof IOCExpireSchema>;

/** POST /v1/iocs/:id/verdict — Assign analyst verdict */
export const IOCVerdictSchema = z.object({
    verdict: z.enum(['malicious', 'suspicious', 'benign', 'unknown']),
    notes: z.string().max(5000).optional(),
});
export type IOCVerdict = z.infer<typeof IOCVerdictSchema>;

/** PUT /v1/sightings/:id — Update sighting */
export const SightingUpdateSchema = z.object({
    source: z.string().min(1).max(200).optional(),
    type: z.enum(['sighting', 'false-positive', 'expiration']).optional(),
    description: z.string().max(2000).optional(),
    confidence: z.number().min(0).max(100).optional(),
}).refine(obj => Object.keys(obj).length > 0, 'At least one field must be specified');
export type SightingUpdate = z.infer<typeof SightingUpdateSchema>;

// ============================================================================
// Phase AE — Taxonomy & Tag Namespace System (MISP inspired)
// ============================================================================

/** POST /v1/taxonomies — Create a custom taxonomy */
export const CreateTaxonomySchema = z.object({
    namespace: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/, 'namespace must be lowercase alphanumeric with hyphens'),
    name: z.string().min(1, 'name is required').max(200),
    description: z.string().max(2000).default(''),
    exclusive: z.boolean().default(false),
});
export type CreateTaxonomy = z.infer<typeof CreateTaxonomySchema>;

/** POST /v1/taxonomies/:namespace/tag — Add tag to taxonomy */
export const AddTaxonomyTagSchema = z.object({
    tag: z.string().min(1, 'tag is required').max(200),
    description: z.string().max(1000).default(''),
    colour: z.string().regex(/^#[0-9a-fA-F]{6}$/).optional(),
    numericValue: z.number().int().min(0).optional(),
});
export type AddTaxonomyTag = z.infer<typeof AddTaxonomyTagSchema>;

// ============================================================================
// Phase AF — Enhanced Export & Sharing (IntelOwl/MISP/TheHive inspired)
// ============================================================================

/** POST /v1/export/misp — Export as MISP event format */
export const MISPExportSchema = z.object({
    entityTypes: z.array(z.enum(['iocs', 'vulnerabilities', 'threat-actors'])).default(['iocs']),
    tlp: z.enum(['white', 'green', 'amber', 'red']).default('green'),
    limit: z.number().int().min(1).max(10000).default(1000),
    dateFrom: z.string().optional(),
    dateTo: z.string().optional(),
});
export type MISPExport = z.infer<typeof MISPExportSchema>;

/** POST /v1/export/rules — Export IOCs as IDS rules (Suricata/Snort) */
export const RuleExportSchema = z.object({
    format: z.enum(['suricata', 'snort']),
    iocTypes: z.array(z.enum(['ip', 'domain', 'url', 'hash'])).default(['ip', 'domain']),
    action: z.enum(['alert', 'drop', 'reject']).default('alert'),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    limit: z.number().int().min(1).max(50000).default(5000),
    sid_start: z.number().int().min(1000000).default(9000000),
});
export type RuleExport = z.infer<typeof RuleExportSchema>;

/** POST /v1/export/report — Generate intelligence report */
export const ReportExportSchema = z.object({
    format: z.enum(['markdown', 'html']).default('markdown'),
    scope: z.enum(['summary', 'full']).default('summary'),
    entityTypes: z.array(z.string()).default(['iocs', 'vulnerabilities']),
    dateFrom: z.string().optional(),
    dateTo: z.string().optional(),
    limit: z.number().int().min(1).max(1000).default(100),
});
export type ReportExport = z.infer<typeof ReportExportSchema>;

// ============================================================================
// Phase AG — CRUD Completeness (TheHive inspired)
// ============================================================================

/** POST /v1/threats/actors — Create a new threat actor */
export const CreateThreatActorSchema = z.object({
    name: z.string().min(1, 'name is required').max(300),
    description: z.string().max(10000).default(''),
    aliases: z.array(z.string()).default([]),
    country: z.string().max(100).optional(),
    sophistication: z.enum(['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic']).optional(),
    resourceLevel: z.enum(['individual', 'club', 'contest', 'team', 'organization', 'government']).optional(),
    primaryMotivation: z.string().max(200).optional(),
    secondaryMotivations: z.array(z.string()).optional(),
    tags: z.array(z.string()).default([]),
});
export type CreateThreatActor = z.infer<typeof CreateThreatActorSchema>;

/** PUT /v1/threats/actors/:id — Update threat actor */
export const UpdateThreatActorSchema = z.object({
    name: z.string().min(1).max(300).optional(),
    description: z.string().max(10000).optional(),
    aliases: z.array(z.string()).optional(),
    country: z.string().max(100).optional(),
    sophistication: z.string().max(100).optional(),
    resourceLevel: z.string().max(100).optional(),
    primaryMotivation: z.string().max(200).optional(),
    tags: z.array(z.string()).optional(),
}).refine(obj => Object.keys(obj).length > 0, 'At least one field must be specified');
export type UpdateThreatActor = z.infer<typeof UpdateThreatActorSchema>;

/** PUT /v1/vulnerabilities/:id — Update vulnerability metadata */
export const UpdateVulnerabilitySchema = z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
    notes: z.string().max(10000).optional(),
    tags: z.array(z.string()).optional(),
    exploited: z.boolean().optional(),
}).refine(obj => Object.keys(obj).length > 0, 'At least one field must be specified');
export type UpdateVulnerability = z.infer<typeof UpdateVulnerabilitySchema>;

/** POST /v1/vulnerabilities/:id/link — Link IOC to vulnerability */
export const VulnLinkIOCSchema = z.object({
    iocId: z.string().uuid('Must be a valid IOC UUID'),
    relationship: z.enum(['exploits', 'indicates', 'mitigates', 'related-to']).default('related-to'),
    notes: z.string().max(2000).optional(),
});
export type VulnLinkIOC = z.infer<typeof VulnLinkIOCSchema>;

/** POST /v1/alerts/:id/escalate — Escalate alert (TheHive alert→case inspired) */
export const AlertEscalateSchema = z.object({
    priority: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
    assignee: z.string().max(200).optional(),
    notes: z.string().max(5000).optional(),
    tags: z.array(z.string()).default([]),
});
export type AlertEscalate = z.infer<typeof AlertEscalateSchema>;

// ============================================================================
// Phase 7 — Case / Investigation Management (TheHive inspired)
// ============================================================================

/** POST /v1/cases — Create investigation case */
export const CreateCaseSchema = z.object({
    title: z.string().min(1).max(500),
    description: z.string().max(10000).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
    status: z.enum(['open', 'in-progress', 'resolved', 'closed']).default('open'),
    assignee: z.string().max(200).optional(),
    tlp: z.enum(['white', 'green', 'amber', 'red']).default('green'),
    tags: z.array(z.string()).default([]),
});
export type CreateCase = z.infer<typeof CreateCaseSchema>;

/** PUT /v1/cases/:id — Update case */
export const UpdateCaseSchema = z.object({
    title: z.string().min(1).max(500).optional(),
    description: z.string().max(10000).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    status: z.enum(['open', 'in-progress', 'resolved', 'closed']).optional(),
    assignee: z.string().max(200).nullable().optional(),
    tlp: z.enum(['white', 'green', 'amber', 'red']).optional(),
    tags: z.array(z.string()).optional(),
    resolution: z.string().max(5000).optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });
export type UpdateCase = z.infer<typeof UpdateCaseSchema>;

/** GET /v1/cases — List cases with filters */
export const CaseFilterSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(20),
    status: z.enum(['open', 'in-progress', 'resolved', 'closed']).optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    assignee: z.string().optional(),
    q: z.string().optional(),
});

/** POST /v1/cases/:id/observables — Attach observable to case */
export const CaseObservableSchema = z.object({
    entityType: z.enum(['ioc', 'vulnerability', 'threat-actor']),
    entityId: z.string().min(1),
    notes: z.string().max(2000).optional(),
    tags: z.array(z.string()).default([]),
});
export type CaseObservable = z.infer<typeof CaseObservableSchema>;

/** POST /v1/cases/:id/tasks — Add task to case */
export const CaseTaskSchema = z.object({
    title: z.string().min(1).max(500),
    description: z.string().max(5000).optional(),
    status: z.enum(['todo', 'in-progress', 'done']).default('todo'),
    assignee: z.string().max(200).optional(),
    dueDate: z.string().datetime().optional(),
});
export type CaseTask = z.infer<typeof CaseTaskSchema>;

/** PUT /v1/cases/:id/tasks/:taskId — Update task */
export const UpdateCaseTaskSchema = z.object({
    title: z.string().min(1).max(500).optional(),
    description: z.string().max(5000).optional(),
    status: z.enum(['todo', 'in-progress', 'done']).optional(),
    assignee: z.string().max(200).nullable().optional(),
    dueDate: z.string().datetime().nullable().optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });

/** POST /v1/cases/:id/timeline — Add timeline entry */
export const CaseTimelineSchema = z.object({
    entryType: z.enum(['comment', 'action', 'status-change', 'evidence']).default('comment'),
    content: z.string().min(1).max(10000),
});

/** POST /v1/cases/from-alert/:alertId — Create case from alert */
export const CaseFromAlertSchema = z.object({
    title: z.string().min(1).max(500).optional(),
    assignee: z.string().max(200).optional(),
    tags: z.array(z.string()).default([]),
});

// ============================================================================
// Phase 8 — Community Blocklist & IP Reputation (CrowdSec inspired)
// ============================================================================

/** POST /v1/reputation/report — Submit community report */
export const ReputationReportSchema = z.object({
    value: z.string().min(1),
    type: z.enum(['ip', 'domain', 'url', 'email']),
    category: z.enum(['malware', 'phishing', 'spam', 'scanning', 'brute-force', 'c2', 'other']).default('other'),
    confidence: z.number().int().min(0).max(100).default(70),
    notes: z.string().max(2000).optional(),
    ttlHours: z.number().int().min(1).max(8760).default(720), // default 30 days
});
export type ReputationReport = z.infer<typeof ReputationReportSchema>;

/** POST /v1/reputation/bulk — Bulk reputation check */
export const BulkReputationSchema = z.object({
    values: z.array(z.string().min(1)).min(1).max(100),
    type: z.enum(['ip', 'domain', 'url', 'email', 'auto']).default('auto'),
});

// ============================================================================
// Phase 9 — Multi-Analyzer Pipeline (Cortex / IntelOwl inspired)
// ============================================================================

/** POST /v1/analyzers/run — Run analyzer(s) on observable */
export const RunAnalyzerSchema = z.object({
    value: z.string().min(1),
    type: z.enum(['ip', 'domain', 'url', 'hash', 'email', 'auto']).default('auto'),
    analyzers: z.array(z.string()).min(1).max(20),
});
export type RunAnalyzer = z.infer<typeof RunAnalyzerSchema>;

/** POST /v1/analyzers/scan-chain — Ordered scan chain */
export const ScanChainSchema = z.object({
    value: z.string().min(1),
    type: z.enum(['ip', 'domain', 'url', 'hash', 'email', 'auto']).default('auto'),
    chain: z.array(z.string()).min(1).max(10),
    stopOnMalicious: z.boolean().default(false),
});
export type ScanChain = z.infer<typeof ScanChainSchema>;

// ============================================================================
// Phase 11 — IOC Watchlists (Recorded Future / MISP inspired)
// ============================================================================

/** POST /v1/watchlists — Create watchlist */
export const CreateWatchlistSchema = z.object({
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    visibility: z.enum(['personal', 'team', 'global']).default('personal'),
    notifyOnHit: z.boolean().default(false),
    tags: z.array(z.string()).default([]),
});
export type CreateWatchlist = z.infer<typeof CreateWatchlistSchema>;

/** PUT /v1/watchlists/:id — Update watchlist */
export const UpdateWatchlistSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(2000).optional(),
    visibility: z.enum(['personal', 'team', 'global']).optional(),
    notifyOnHit: z.boolean().optional(),
    tags: z.array(z.string()).optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });

/** POST /v1/watchlists/:id/entries — Add entry to watchlist */
export const WatchlistEntrySchema = z.object({
    value: z.string().min(1).max(500),
    type: z.enum(['ip', 'domain', 'url', 'hash', 'email', 'cidr']),
    notes: z.string().max(2000).optional(),
    expiresAt: z.string().datetime().optional(),
});

/** POST /v1/watchlists/check — Check value against watchlists */
export const WatchlistCheckSchema = z.object({
    value: z.string().min(1),
});

// ============================================================================
// Phase 12 — Scheduled Intelligence Reports
// ============================================================================

/** POST /v1/reports/schedules — Create report schedule */
export const CreateReportScheduleSchema = z.object({
    name: z.string().min(1).max(200),
    schedule: z.enum(['daily', 'weekly', 'monthly']).default('weekly'),
    format: z.enum(['markdown', 'html']).default('markdown'),
    scope: z.enum(['summary', 'detailed', 'full']).default('summary'),
    filters: z.object({
        entityTypes: z.array(z.string()).optional(),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
        dateRange: z.enum(['24h', '7d', '30d']).default('7d'),
    }).default({}),
    delivery: z.object({
        email: z.string().email().optional(),
        slack: z.boolean().default(false),
        inApp: z.boolean().default(true),
    }).default({}),
    enabled: z.boolean().default(true),
});
export type CreateReportSchedule = z.infer<typeof CreateReportScheduleSchema>;

/** PUT /v1/reports/schedules/:id */
export const UpdateReportScheduleSchema = z.object({
    name: z.string().min(1).max(200).optional(),
    schedule: z.enum(['daily', 'weekly', 'monthly']).optional(),
    format: z.enum(['markdown', 'html']).optional(),
    scope: z.enum(['summary', 'detailed', 'full']).optional(),
    filters: z.object({
        entityTypes: z.array(z.string()).optional(),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
        dateRange: z.enum(['24h', '7d', '30d']).optional(),
    }).optional(),
    delivery: z.object({
        email: z.string().email().optional(),
        slack: z.boolean().optional(),
        inApp: z.boolean().optional(),
    }).optional(),
    enabled: z.boolean().optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });

// ============================================================================
// Phase 13 — IOC Relationship Management (STIX SRO inspired)
// ============================================================================

// Source vocab kept narrow on purpose — these are the entity types the UI
// can render today. Adding 'campaign', 'course-of-action', 'infrastructure'
// (Phase 2 #1 entity tables) widened this; B1.2 adds the telco entity types
// (+ fight-technique for the relational bridge to MITRE FiGHT — the graph
// edge to FiGHT is deferred until FiGHT nodes are synced to Neo4j).
const RELATIONSHIP_ENTITY_TYPES = [
    'ioc', 'vulnerability', 'threat-actor', 'campaign', 'malware', 'tool',
    'course-of-action', 'infrastructure',
    // Telco vertical (B1.2)
    'network-element', 'signaling-interface', 'fraud-scheme', 'fight-technique',
    // On-chain / follow-the-money (AA.6.2 / Phase 8)
    'wallet',
    // MITRE ATLAS (AI) techniques (FW.1) — fight-technique above now graph-bridged too
    'atlas-technique',
] as const;

/** POST /v1/relationships — Create explicit relationship */
export const CreateRelationshipSchema = z.object({
    sourceType: z.enum(RELATIONSHIP_ENTITY_TYPES),
    sourceId: z.string().min(1),
    targetType: z.enum(RELATIONSHIP_ENTITY_TYPES),
    targetId: z.string().min(1),
    // Sourced from @rinjani/core/stixVocab — the canonical STIX 2.1 §5.7
    // SRO vocab + project-specific extensions. Kept in sync with the DB
    // CHECK constraint added in migration 0045_relationship_type_check.sql.
    relationshipType: z.enum(STIX_RELATIONSHIP_TYPES),
    confidence: z.number().int().min(0).max(100).default(70),
    description: z.string().max(2000).optional(),
});
export type CreateRelationship = z.infer<typeof CreateRelationshipSchema>;

/** POST /v1/relationships/bulk — Bulk create */
export const BulkRelationshipSchema = z.object({
    relationships: z.array(CreateRelationshipSchema).min(1).max(100),
});

/** GET /v1/relationships — Filter params */
export const RelationshipFilterSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(20),
    sourceType: z.string().optional(),
    targetType: z.string().optional(),
    relationshipType: z.string().optional(),
    entityId: z.string().optional(),
});

// ============================================================================
// Phase 14 — Threat Landscape API
// ============================================================================

/** GET /v1/landscape/* — Query params */
export const LandscapeQuerySchema = z.object({
    period: z.enum(['24h', '7d', '30d', '90d']).default('7d'),
    limit: z.coerce.number().int().min(1).max(100).default(20),
});

// ============================================================================
// Phase 17 — IOC Comments & Annotations (TheHive inspired)
// ============================================================================

export const CreateCommentSchema = z.object({
    entityType: z.enum(['ioc', 'vulnerability', 'threat-actor', 'campaign', 'case']),
    entityId: z.string().min(1),
    content: z.string().min(1).max(5000),
    visibility: z.enum(['public', 'team', 'private']).default('public'),
    pinned: z.boolean().default(false),
});

export const UpdateCommentSchema = z.object({
    content: z.string().min(1).max(5000).optional(),
    visibility: z.enum(['public', 'team', 'private']).optional(),
    pinned: z.boolean().optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });

// ============================================================================
// Phase 18 — Data Retention Policies
// ============================================================================

export const CreateRetentionPolicySchema = z.object({
    name: z.string().min(1).max(200),
    entityType: z.enum(['ioc', 'vulnerability', 'alert', 'sighting', 'audit_log', 'notification']),
    retentionDays: z.number().int().min(1).max(3650),
    action: z.enum(['delete', 'archive', 'anonymize']).default('delete'),
    filters: z.object({
        severity: z.string().optional(),
        source: z.string().optional(),
        maxRiskScore: z.number().int().min(0).max(100).optional(),
    }).default({}),
    enabled: z.boolean().default(true),
});

export const UpdateRetentionPolicySchema = z.object({
    name: z.string().min(1).max(200).optional(),
    retentionDays: z.number().int().min(1).max(3650).optional(),
    action: z.enum(['delete', 'archive', 'anonymize']).optional(),
    filters: z.object({
        severity: z.string().optional(),
        source: z.string().optional(),
        maxRiskScore: z.number().int().min(0).max(100).optional(),
    }).optional(),
    enabled: z.boolean().optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });

// ============================================================================
// Phase 19 — Enrichment Provider Management
// ============================================================================

export const UpdateEnrichmentProviderSchema = z.object({
    enabled: z.boolean().optional(),
    priority: z.number().int().min(1).max(100).optional(),
    apiKey: z.string().optional(),
    rateLimit: z.number().int().min(0).optional(),
    timeout: z.number().int().min(1000).max(60000).optional(),
}).refine(d => Object.values(d).some(v => v !== undefined), { message: 'At least one field required' });
