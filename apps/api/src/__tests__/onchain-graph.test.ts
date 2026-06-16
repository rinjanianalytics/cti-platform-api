/**
 * AA.6.2 on-chain graph boundary tests — same traps B1.2 guards:
 *
 *  1. silent edge skip — labelForEntityType('wallet') must resolve, or
 *     cashed-out-to / sent-funds-to / controls-wallet edges never hydrate.
 *  2. multi-layer vocab mismatch — the fund-flow verbs must agree across the
 *     three copies (DB CHECK / STIX_RELATIONSHIP_TYPES / RELATIONSHIP_ENTITY_TYPES);
 *     we assert the two zod copies carry them + the 'wallet' entity type.
 *  3. the node mapper sets id=refId, the autoHydrate MATCH key.
 */

import { describe, expect, it } from 'vitest';
import { labelForEntityType } from '../services/neo4j';
import { toWalletNode } from '../services/neo4j/syncEntities/onchainSync';
import { STIX_RELATIONSHIP_TYPES } from '@rinjani/core/stixVocab';
import { CreateRelationshipSchema } from '../lib/schemas';

describe('Neo4j label map resolves the wallet entity type (guards the silent-skip)', () => {
    it('wallet → Wallet', () => {
        expect(labelForEntityType('wallet')).toBe('Wallet');
    });
    it('is case-insensitive', () => {
        expect(labelForEntityType('Wallet')).toBe('Wallet');
    });
});

describe('Fund-flow vocab agrees across layers (guards the multi-layer mismatch)', () => {
    const verbs = ['sent-funds-to', 'controls-wallet', 'cashed-out-to'];

    it('STIX_RELATIONSHIP_TYPES includes every fund-flow verb', () => {
        for (const v of verbs) {
            expect(STIX_RELATIONSHIP_TYPES as readonly string[]).toContain(v);
        }
    });

    it('CreateRelationshipSchema accepts the fraud-scheme → wallet cashout bridge', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'fraud-scheme',
            sourceId: 'sim-swap:port-out',
            targetType: 'wallet',
            targetId: 'eth:0xdeadbeef',
            relationshipType: 'cashed-out-to',
        });
        expect(r.success).toBe(true);
    });

    it('CreateRelationshipSchema accepts wallet → wallet fund flow', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'wallet', sourceId: 'eth:0xa',
            targetType: 'wallet', targetId: 'eth:0xb',
            relationshipType: 'sent-funds-to',
        });
        expect(r.success).toBe(true);
    });

    it('still rejects an unknown verb on a wallet relationship', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'wallet', sourceId: 'eth:0xa',
            targetType: 'wallet', targetId: 'eth:0xb',
            relationshipType: 'rug-pulled',
        });
        expect(r.success).toBe(false);
    });
});

describe('toWalletNode sets id=refId (the hydrate MATCH key) + carries confidence', () => {
    const now = new Date();
    it('id === refId, attribution rides with confidence', () => {
        const node = toWalletNode({
            id: 'pg-uuid-1', stixId: null, refId: 'eth:0xdeadbeef', address: '0xdeadbeef',
            chain: 'eth', name: 'cashout', description: 'd',
            entityLabel: 'Sim-swap cashout', entityType: 'personal',
            confidence: 65, attributionSource: 'manual',
            riskTags: ['sim-swap-cashout'], externalReferences: [], labels: [],
            createdAt: now, updatedAt: now,
        } as never);
        expect(node.id).toBe('eth:0xdeadbeef');     // == refId → autoHydrate MATCH src.id
        expect(node.refId).toBe('eth:0xdeadbeef');
        expect(node.pgId).toBe('pg-uuid-1');
        expect(node.confidence).toBe(65);            // never asserted as fact — rides with the label
        expect(node.entityLabel).toBe('Sim-swap cashout');
        expect(node.riskTags).toEqual(['sim-swap-cashout']);
    });

    it('truncates a long description to 500 chars', () => {
        const node = toWalletNode({
            id: 'x', stixId: null, refId: 'eth:0x', address: '0x', chain: 'eth',
            name: null, description: 'a'.repeat(900), entityLabel: null, entityType: null,
            confidence: 50, attributionSource: null, riskTags: [], externalReferences: [], labels: [],
            createdAt: now, updatedAt: now,
        } as never);
        expect(node.description.length).toBe(500);
    });
});
