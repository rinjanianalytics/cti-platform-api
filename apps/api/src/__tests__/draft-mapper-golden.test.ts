/**
 * Golden-output evals for draftMapper.
 *
 * These are NOT real LLM calls. The "golden" property we lock in is:
 *   Given a realistic LLM response for a realistic feed sample, our
 *   pipeline produces a status='ok' result with a manifest whose dry-run
 *   matches the expected canonical shape.
 *
 * What this exercises end-to-end (vs draft-mapper.test.ts which mocks at
 * the unit boundary): the closed-vocab parsing, every transform op the
 * eval uses, zod validation of the LLM output, and the dry-run shape.
 *
 * To run real-LLM evals against the same fixtures, use
 *   pnpm --filter @rinjani/api test:llm:eval
 * (intentionally separate so CI never flakes on provider outages or
 * model-version drift).
 */

import { describe, expect, it, vi } from 'vitest';

vi.mock('../services/aiMiddleware/callLLM', () => ({
    callLLM: vi.fn(),
}));

import { draftMapper } from '../services/draftMapper';
import { callLLM } from '../services/aiMiddleware/callLLM';

// ============================================================================
// Fixture 1 — ThreatFox-shaped JSON, IOC entity
// ============================================================================

const THREATFOX_SAMPLE = JSON.stringify({
    query_status: 'ok',
    data: [
        { ioc: '203.0.113.5:443', ioc_type: 'ip:port', threat_type: 'botnet_cc', confidence_level: 100, first_seen: '2026-06-15 10:00:00 UTC', tags: ['qakbot', 'c2'] },
        { ioc: 'malicious.example.org', ioc_type: 'domain', threat_type: 'payload_delivery', confidence_level: 75, first_seen: '2026-06-15 11:00:00 UTC', tags: null },
        { ioc: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', ioc_type: 'sha256_hash', threat_type: 'payload_delivery', confidence_level: 50, first_seen: '2026-06-15 12:00:00 UTC', tags: ['cobaltstrike'] },
    ],
});

const THREATFOX_GOLDEN_LLM_OUTPUT = JSON.stringify({
    id: 'threatfox',
    name: 'abuse.ch ThreatFox',
    enabled: true,
    entity: 'ioc',
    source: { url: 'https://threatfox-api.abuse.ch/api/v1/', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: { query: 'get_iocs', days: 7 }, auth: { type: 'apiKeyHeader', header: 'Auth-Key' } },
    format: 'json',
    extract: { recordsPath: 'data' },
    mapping: {
        value: { from: 'ioc', transforms: [{ op: 'trim' }], required: true },
        type: {
            from: 'ioc_type',
            transforms: [
                { op: 'mapEnum', arg: { table: { 'ip:port': 'ip', 'domain': 'domain', 'url': 'url', 'md5_hash': 'hash-md5', 'sha1_hash': 'hash-sha1', 'sha256_hash': 'hash-sha256' }, fallback: 'unknown' } },
            ],
            required: true,
        },
        source: { literal: 'threatfox' },
        threatType: {
            from: 'threat_type',
            transforms: [
                { op: 'mapEnum', arg: { table: { 'botnet_cc': 'c2', 'payload_delivery': 'malware', 'ransomware_payment_site': 'ransomware', 'phishing': 'phishing' }, fallback: 'malware' } },
            ],
        },
        confidence: { from: 'confidence_level', transforms: [{ op: 'toNumber' }] },
        severity: {
            from: 'confidence_level',
            transforms: [
                { op: 'bucketize', arg: { ranges: [{ min: 75, value: 'high' }, { min: 50, max: 74, value: 'medium' }], fallback: 'low' } },
            ],
        },
        firstSeen: { from: 'first_seen', transforms: [{ op: 'toIso' }] },
    },
});

describe('golden eval — ThreatFox sample produces a parser that extracts all 3 records', () => {
    it('LLM-shaped output → status=ok with read=3 / ok=3 / failed=0', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: THREATFOX_GOLDEN_LLM_OUTPUT,
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 412, tokensUsed: 1240,
        });

        const result = await draftMapper({
            sample: THREATFOX_SAMPLE,
            format: 'json',
            entity: 'ioc',
            sourceName: 'threatfox',
        });

        expect(result.status).toBe('ok');
        expect(result.dryRun).toEqual({ read: 3, ok: 3, failed: 0, errors: [] });
        expect(result.manifest.mapping).toHaveProperty('value');
        expect(result.manifest.mapping).toHaveProperty('type');
        expect(result.manifest.mapping).toHaveProperty('threatType');
        expect(result.manifest.mapping).toHaveProperty('severity');
        // bucketize + mapEnum + toIso all exercised; if any failed, dry-run wouldn't be ok=3.
    });
});

// ============================================================================
// Fixture 2 — URLhaus-shaped CSV, IOC entity
// ============================================================================

// Note: the real URLhaus CSV starts with `# ...` banner lines that the seed
// CSV parser doesn't strip. Locking in the eval against the post-banner shape
// — operators paste the records-with-header slice into the suggest endpoint.
// `#`-comment-skipping is a documented vocab gap (deferred until a feed
// needs it as a hard requirement).
const URLHAUS_SAMPLE = [
    'id,dateadded,url,url_status,threat,tags',
    '1,2026-06-14 10:00:00,http://bad.example.com/x.exe,online,malware_download,"trojan,qakbot"',
    '2,2026-06-14 11:00:00,http://other.example.org/login,online,phishing,"phishing"',
    '3,2026-06-14 12:00:00,http://offline.example.net/payload,offline,malware_download,""',
].join('\n');

const URLHAUS_GOLDEN_LLM_OUTPUT = JSON.stringify({
    id: 'urlhaus',
    name: 'abuse.ch URLhaus',
    enabled: true,
    entity: 'ioc',
    source: { url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', method: 'GET', headers: {}, auth: { type: 'none' } },
    format: 'csv',
    extract: { csv: { delimiter: ',', hasHeader: true } },
    mapping: {
        value: { from: 'url', transforms: [{ op: 'trim' }], required: true },
        type: { literal: 'url', required: true },
        source: { literal: 'urlhaus' },
        severity: {
            from: 'url_status',
            transforms: [
                { op: 'mapEnum', arg: { table: { online: 'high', offline: 'medium' }, fallback: 'low' } },
            ],
        },
        tags: {
            from: 'tags',
            transforms: [
                { op: 'split', arg: { sep: ',' } },
                { op: 'prepend', arg: ['urlhaus'] },
            ],
        },
        firstSeen: { from: 'dateadded', transforms: [{ op: 'toIso' }] },
    },
});

describe('golden eval — URLhaus CSV sample produces a parser with header + quoted tags', () => {
    it('LLM-shaped output → status=ok with read=3 / ok=3 / failed=0', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: URLHAUS_GOLDEN_LLM_OUTPUT,
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 580, tokensUsed: 1100,
        });

        const result = await draftMapper({
            sample: URLHAUS_SAMPLE,
            format: 'csv',
            entity: 'ioc',
            sourceName: 'urlhaus',
        });

        expect(result.status).toBe('ok');
        expect(result.dryRun).toEqual({ read: 3, ok: 3, failed: 0, errors: [] });
        expect(result.manifest.mapping.tags).toBeDefined();
        expect(result.manifest.mapping.severity).toBeDefined();
        // split + prepend chained on tags — exercises the multi-op pipeline
    });
});

// ============================================================================
// Fixture 3 — CISA KEV-shaped JSON, vulnerability entity
// ============================================================================

const CISA_KEV_SAMPLE = JSON.stringify({
    title: 'CISA Known Exploited Vulnerabilities Catalog',
    catalogVersion: '2026.06.15',
    vulnerabilities: [
        {
            cveID: 'CVE-2026-12345', vendorProject: 'Apache', product: 'Struts',
            vulnerabilityName: 'Apache Struts RCE', dateAdded: '2026-06-10',
            shortDescription: 'Remote code execution in Struts via OGNL injection.',
            requiredAction: 'Patch to latest version.', dueDate: '2026-07-01',
        },
        {
            cveID: 'CVE-2026-22222', vendorProject: 'Microsoft', product: 'Windows',
            vulnerabilityName: 'Win32k Elevation of Privilege', dateAdded: '2026-06-12',
            shortDescription: 'Local privilege escalation in win32k.sys.',
            requiredAction: 'Apply June 2026 security updates.', dueDate: '2026-07-03',
        },
    ],
});

const CISA_GOLDEN_LLM_OUTPUT = JSON.stringify({
    id: 'cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities',
    enabled: true,
    entity: 'vulnerability',
    source: { url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', method: 'GET', headers: {}, auth: { type: 'none' } },
    format: 'json',
    extract: { recordsPath: 'vulnerabilities' },
    mapping: {
        cveId: { from: 'cveID', transforms: [{ op: 'trim' }, { op: 'upper' }], required: true },
        source: { literal: 'cisa-kev' },
        description: { from: 'shortDescription' },
        vendorProject: { from: 'vendorProject' },
        product: { from: 'product' },
        isExploited: { literal: true },
    },
});

describe('golden eval — CISA KEV sample produces a vulnerability-entity parser', () => {
    it('LLM-shaped output → status=ok with read=2 / ok=2 / failed=0', async () => {
        vi.mocked(callLLM).mockResolvedValue({
            text: CISA_GOLDEN_LLM_OUTPUT,
            provider: 'gemini', model: 'gemini-2.0-flash', latencyMs: 380, tokensUsed: 980,
        });

        const result = await draftMapper({
            sample: CISA_KEV_SAMPLE,
            format: 'json',
            entity: 'vulnerability',
            sourceName: 'cisa-kev',
            recordsPathHint: 'vulnerabilities',
        });

        expect(result.status).toBe('ok');
        expect(result.dryRun).toEqual({ read: 2, ok: 2, failed: 0, errors: [] });
        expect(result.manifest.entity).toBe('vulnerability');
        expect(result.manifest.mapping).toHaveProperty('cveId');
        expect(result.manifest.mapping).toHaveProperty('isExploited');
    });
});
