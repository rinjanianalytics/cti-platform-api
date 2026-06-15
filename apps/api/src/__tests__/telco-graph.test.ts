/**
 * B1.2 boundary tests — guard the two traps the fact-check surfaced:
 *
 *  1. The "silent edge skip": if a telco entity type isn't in
 *     NEO4J_LABEL_BY_ENTITY, autoHydrateRelationship returns early and the
 *     edge never appears in the graph — no error. labelForEntityType() must
 *     resolve every telco type.
 *
 *  2. The "multi-layer vocab mismatch": the relationship vocab lives in THREE
 *     places that must agree (DB CHECK, STIX_RELATIONSHIP_TYPES zod,
 *     RELATIONSHIP_ENTITY_TYPES zod). If they drift, telco relationships are
 *     rejected at one layer. We assert the zod copies carry the telco verbs +
 *     entity types.
 *
 *  3. The pure node-mappers (toXNode) produce the id=refId match key the
 *     hydrate depends on.
 */

import { describe, expect, it } from 'vitest';
import { labelForEntityType } from '../services/neo4j';
import {
    toNetworkElementNode, toSignalingInterfaceNode, toFraudSchemeNode,
} from '../services/neo4j/syncEntities/telcoSync';
import { STIX_RELATIONSHIP_TYPES } from '@rinjani/core/stixVocab';
import { CreateRelationshipSchema } from '../lib/schemas';

describe('Neo4j label map resolves telco entity types (guards the silent-skip)', () => {
    it.each([
        ['network-element', 'NetworkElement'],
        ['network_element', 'NetworkElement'],
        ['signaling-interface', 'SignalingInterface'],
        ['signaling_interface', 'SignalingInterface'],
        ['fraud-scheme', 'FraudScheme'],
        ['fraud_scheme', 'FraudScheme'],
    ])('%s → %s', (input, label) => {
        expect(labelForEntityType(input)).toBe(label);
    });

    it('is case-insensitive', () => {
        expect(labelForEntityType('Network-Element')).toBe('NetworkElement');
    });

    it('fight-technique is intentionally NOT graph-participating yet (relational bridge only)', () => {
        // FiGHT isn't synced to Neo4j; the fraud_scheme→fight_technique edge is
        // deferred. labelForEntityType must return null so the hydrate skips
        // cleanly rather than MERGE-ing a phantom node.
        expect(labelForEntityType('fight-technique')).toBeNull();
    });

    it('unknown types return null (not a crash)', () => {
        expect(labelForEntityType('banana')).toBeNull();
    });
});

describe('Relationship vocab stays in sync across layers (guards the multi-layer mismatch)', () => {
    const telcoVerbs = ['connects-to', 'uses-interface', 'enables-fraud', 'exploits-via'];

    it('STIX_RELATIONSHIP_TYPES (route zod) includes every telco verb', () => {
        for (const v of telcoVerbs) {
            expect(STIX_RELATIONSHIP_TYPES as readonly string[]).toContain(v);
        }
    });

    it('CreateRelationshipSchema accepts a telco relationship end to end', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'fraud-scheme',
            sourceId: 'sim-swap:port-out',
            targetType: 'signaling-interface',
            targetId: 'diameter:s6a',
            relationshipType: 'exploits-via',
        });
        expect(r.success).toBe(true);
    });

    it('CreateRelationshipSchema accepts the relational fraud-scheme → fight-technique bridge', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'fraud-scheme',
            sourceId: 'irsf:premium',
            targetType: 'fight-technique',
            targetId: 'FGT5004',
            relationshipType: 'uses',
        });
        expect(r.success).toBe(true);
    });

    it('still rejects an unknown relationship verb (CHECK vocab is closed)', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'fraud-scheme', sourceId: 'a',
            targetType: 'signaling-interface', targetId: 'b',
            relationshipType: 'definitely-not-a-verb',
        });
        expect(r.success).toBe(false);
    });

    it('still rejects an unknown entity type', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'spaceship', sourceId: 'a',
            targetType: 'signaling-interface', targetId: 'b',
            relationshipType: 'connects-to',
        });
        expect(r.success).toBe(false);
    });
});

describe('Telco node mappers set id=refId (the hydrate MATCH key)', () => {
    const now = new Date();
    const base = { id: 'pg-uuid-1', stixId: null, description: 'd', createdAt: now, updatedAt: now };

    it('network element node: id === refId, carries pgId + props', () => {
        const node = toNetworkElementNode({
            ...base, refId: 'ericsson:hss:core', name: 'HSS', elementType: 'HSS',
            architectureSegment: 'Core', vendor: ['Ericsson'], interfaces: [],
            externalReferences: [], labels: [],
        } as never);
        expect(node.id).toBe('ericsson:hss:core');     // == refId → autoHydrate MATCH src.id
        expect(node.refId).toBe('ericsson:hss:core');
        expect(node.pgId).toBe('pg-uuid-1');
        expect(node.elementType).toBe('HSS');
    });

    it('signaling interface node: id === refId', () => {
        const node = toSignalingInterfaceNode({
            ...base, refId: 'diameter:s6a', name: 'S6a', protocol: 'Diameter',
            referencePoint: 'S6a', specRef: '3GPP TS 29.272',
            externalReferences: [], labels: [],
        } as never);
        expect(node.id).toBe('diameter:s6a');
        expect(node.protocol).toBe('Diameter');
    });

    it('fraud scheme node: id === refId, carries gsma categories', () => {
        const node = toFraudSchemeNode({
            ...base, refId: 'sim-swap:port-out', name: 'SIM swap', schemeType: 'sim-swap',
            monetization: 'ato', gsmaFsCategories: ['FS.11'], killChainPhases: [],
            externalReferences: [], labels: [],
        } as never);
        expect(node.id).toBe('sim-swap:port-out');
        expect(node.gsmaFsCategories).toEqual(['FS.11']);
    });

    it('truncates long descriptions to 500 chars (Neo4j prop hygiene)', () => {
        const node = toNetworkElementNode({
            ...base, refId: 'x', name: 'x', elementType: 'HSS', architectureSegment: null,
            vendor: [], interfaces: [], externalReferences: [], labels: [],
            description: 'a'.repeat(900),
        } as never);
        expect(node.description.length).toBe(500);
    });
});
