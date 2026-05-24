/**
 * Schema Validation Tests — Wave 4 (Phases 16–19)
 */

import { describe, it, expect } from 'vitest';
import {
    CreateCommentSchema, UpdateCommentSchema,
    CreateRetentionPolicySchema, UpdateRetentionPolicySchema,
    UpdateEnrichmentProviderSchema,
} from '../lib/schemas';

// Phase 16: Campaign schemas — removed when Nexus was ripped out.

// Phase 17: Comments
describe('CreateCommentSchema', () => {
    it('requires entityType, entityId, content', () => { expect(() => CreateCommentSchema.parse({})).toThrow(); });
    it('accepts full comment', () => {
        const r = CreateCommentSchema.parse({
            entityType: 'ioc', entityId: 'abc', content: 'Looks suspicious',
            visibility: 'team', pinned: true,
        });
        expect(r.visibility).toBe('team');
        expect(r.pinned).toBe(true);
    });
    it('defaults visibility to public', () => {
        const r = CreateCommentSchema.parse({ entityType: 'campaign', entityId: 'x', content: 'Note' });
        expect(r.visibility).toBe('public');
    });
    it('supports case entity type', () => {
        const r = CreateCommentSchema.parse({ entityType: 'case', entityId: 'x', content: 'Test' });
        expect(r.entityType).toBe('case');
    });
});

describe('UpdateCommentSchema', () => {
    it('rejects empty', () => { expect(() => UpdateCommentSchema.parse({})).toThrow(); });
    it('accepts pin toggle', () => { expect(UpdateCommentSchema.parse({ pinned: true }).pinned).toBe(true); });
});

// Phase 18: Retention
describe('CreateRetentionPolicySchema', () => {
    it('requires name, entityType, retentionDays', () => { expect(() => CreateRetentionPolicySchema.parse({})).toThrow(); });
    it('accepts minimal', () => {
        const r = CreateRetentionPolicySchema.parse({ name: 'Old IOCs', entityType: 'ioc', retentionDays: 90 });
        expect(r.action).toBe('delete');
        expect(r.enabled).toBe(true);
    });
    it('accepts archive action with filters', () => {
        const r = CreateRetentionPolicySchema.parse({
            name: 'Stale alerts', entityType: 'alert', retentionDays: 30,
            action: 'archive', filters: { severity: 'low', maxRiskScore: 20 },
        });
        expect(r.action).toBe('archive');
    });
    it('rejects invalid entity type', () => {
        expect(() => CreateRetentionPolicySchema.parse({ name: 'x', entityType: 'user', retentionDays: 30 })).toThrow();
    });
    it('enforces max 3650 days', () => {
        expect(() => CreateRetentionPolicySchema.parse({ name: 'x', entityType: 'ioc', retentionDays: 5000 })).toThrow();
    });
});

describe('UpdateRetentionPolicySchema', () => {
    it('rejects empty', () => { expect(() => UpdateRetentionPolicySchema.parse({})).toThrow(); });
    it('accepts days change', () => { expect(UpdateRetentionPolicySchema.parse({ retentionDays: 180 }).retentionDays).toBe(180); });
});

// Phase 19: Enrichment Providers
describe('UpdateEnrichmentProviderSchema', () => {
    it('rejects empty', () => { expect(() => UpdateEnrichmentProviderSchema.parse({})).toThrow(); });
    it('accepts enable toggle', () => { expect(UpdateEnrichmentProviderSchema.parse({ enabled: false }).enabled).toBe(false); });
    it('accepts priority', () => { expect(UpdateEnrichmentProviderSchema.parse({ priority: 10 }).priority).toBe(10); });
    it('accepts rate limit and timeout', () => {
        const r = UpdateEnrichmentProviderSchema.parse({ rateLimit: 100, timeout: 5000 });
        expect(r.rateLimit).toBe(100);
        expect(r.timeout).toBe(5000);
    });
    it('rejects timeout below 1000ms', () => {
        expect(() => UpdateEnrichmentProviderSchema.parse({ timeout: 500 })).toThrow();
    });
});
