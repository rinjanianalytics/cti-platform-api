/**
 * Tests for the actor-summary prompt builder + schema.
 *
 * The end-to-end summariseActor() call hits the DB + the LLM router —
 * not unit-testable. These tests lock the deterministic pieces.
 */
import { describe, it, expect } from 'vitest';
import { buildActorSummaryPrompt } from '../services/actorSummary';
import { ActorSummarySchema } from '../lib/schemas';
import { threatActors } from '@rinjani/db/schema';

type Actor = typeof threatActors.$inferSelect;

const baseActor: Actor = {
    id: 'a1',
    stixId: 'threat-actor--apt28',
    realStixId: null,
    name: 'APT28',
    description: 'A long-running Russian state actor.',
    aliases: ['Fancy Bear', 'Sofacy'],
    country: null,
    sophistication: 'strategic',
    resourceLevel: 'government',
    primaryMotivation: 'organizational-gain',
    secondaryMotivations: ['ideology'],
    confidence: 'high',
    goals: [],
    labels: [],
    externalReferences: [],
    firstSeen: null,
    lastSeen: null,
    createdByRef: null,
    objectMarkingRefs: null,
    stixCreated: null,
    stixModified: null,
    syncedAt: null,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
};

describe('buildActorSummaryPrompt', () => {
    it('embeds the actor name, aliases, and motivations', () => {
        const p = buildActorSummaryPrompt(baseActor, {
            totalRelationships: 0,
            recentRelationships: 0,
            outgoingByType: [],
            recentIOCs: [],
            topMalware: [],
            recentCampaigns: [],
        }, 30);
        expect(p).toContain('APT28');
        expect(p).toContain('Fancy Bear, Sofacy');
        expect(p).toContain('organizational-gain, ideology');
        expect(p).toContain('Last 30 days');
    });

    it('renders activity counts and lists when populated', () => {
        const p = buildActorSummaryPrompt(baseActor, {
            totalRelationships: 42,
            recentRelationships: 7,
            outgoingByType: [
                { targetType: 'malware', relationshipType: 'uses', count: 5 },
                { targetType: 'ioc', relationshipType: 'indicates', count: 12 },
            ],
            recentIOCs: [
                { value: '1.2.3.4', type: 'ip', severity: 'high', lastSeen: '2026-06-01' },
            ],
            topMalware: ['Emotet', 'Cobalt Strike'],
            recentCampaigns: ['Operation Forest'],
        }, 60);

        expect(p).toContain('Total relationships in our graph: 42');
        expect(p).toContain('Relationships touched in window: 7');
        expect(p).toContain('uses → malware: 5');
        expect(p).toContain('Emotet');
        expect(p).toContain('Operation Forest');
        expect(p).toContain('1.2.3.4');
        expect(p).toContain('Last 60 days');
    });

    it('explicitly signals empty data so the LLM does not invent', () => {
        const p = buildActorSummaryPrompt(baseActor, {
            totalRelationships: 0,
            recentRelationships: 0,
            outgoingByType: [],
            recentIOCs: [],
            topMalware: [],
            recentCampaigns: [],
        }, 30);
        expect(p).toContain('(none)');
        expect(p).toContain('(none recorded)');
        expect(p).toContain('(no recent IOCs in window)');
        expect(p).toMatch(/Do NOT hallucinate/);
    });

    it('handles a missing description gracefully', () => {
        const actor = { ...baseActor, description: null };
        const p = buildActorSummaryPrompt(actor, {
            totalRelationships: 0, recentRelationships: 0, outgoingByType: [],
            recentIOCs: [], topMalware: [], recentCampaigns: [],
        }, 30);
        expect(p).toContain('Description: —');
    });
});

describe('ActorSummarySchema', () => {
    it('coerces string `days` to a number', () => {
        const r = ActorSummarySchema.parse({ days: '90' });
        expect(r.days).toBe(90);
    });

    it('defaults days to 30', () => {
        const r = ActorSummarySchema.parse({});
        expect(r.days).toBe(30);
    });

    it('caps days at 365', () => {
        expect(() => ActorSummarySchema.parse({ days: 5000 })).toThrow();
    });

    it('rejects unknown providers', () => {
        expect(() => ActorSummarySchema.parse({ provider: 'gpt-4' })).toThrow();
    });

    it('passes through valid provider override', () => {
        const r = ActorSummarySchema.parse({ provider: 'gemini' });
        expect(r.provider).toBe('gemini');
    });
});
