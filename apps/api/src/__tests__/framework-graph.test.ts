/**
 * FW.1 framework graph tests — FiGHT + ATLAS technique nodes.
 *
 * Guards the same traps as telco/onchain: the label map must resolve the
 * technique entity types (or the fraud_scheme→fight_technique bridge silently
 * never hydrates), and the node mappers must set id = the natural technique id
 * (the autoHydrate MATCH key).
 */

import { describe, expect, it } from 'vitest';
import { labelForEntityType } from '../services/neo4j';
import { toFightTechniqueNode, toAtlasTechniqueNode } from '../services/neo4j/syncEntities/frameworkSync';
import { CreateRelationshipSchema } from '../lib/schemas';

describe('label map resolves FiGHT/ATLAS technique types (guards the silent-skip)', () => {
    it.each([
        ['fight-technique', 'FightTechnique'],
        ['fight_technique', 'FightTechnique'],
        ['atlas-technique', 'AtlasTechnique'],
        ['atlas_technique', 'AtlasTechnique'],
    ])('%s → %s', (input, label) => {
        expect(labelForEntityType(input)).toBe(label);
    });
});

describe('the fraud_scheme → fight_technique bridge is now a valid graph relationship', () => {
    it('CreateRelationshipSchema accepts fraud-scheme -[uses]-> fight-technique', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'fraud-scheme', sourceId: 'sim-swap:port-out',
            targetType: 'fight-technique', targetId: 'FGT5004',
            relationshipType: 'uses',
        });
        expect(r.success).toBe(true);
    });
    it('CreateRelationshipSchema accepts actor -[uses]-> atlas-technique', () => {
        const r = CreateRelationshipSchema.safeParse({
            sourceType: 'threat-actor', sourceId: 'G0001',
            targetType: 'atlas-technique', targetId: 'AML.T0043',
            relationshipType: 'uses',
        });
        expect(r.success).toBe(true);
    });
});

describe('node mappers set id = the technique id (the hydrate MATCH key)', () => {
    const now = new Date();
    it('FiGHT: id === fightId, carries the 5G architecture segment', () => {
        const node = toFightTechniqueNode({
            id: 'pg-1', fightId: 'FGT5004', name: 'SIM-swap', description: 'd', bluf: null,
            status: 'observed', architectureSegment: 'Core', typecode: 'fight_technique',
            tacticIds: ['TA5001'], platforms: ['5G Core'], preconditions: [], postconditions: [],
            criticalAssets: [], detections: [], procedureExamples: [], references: [], url: null,
            createdAt: now, updatedAt: now,
        } as never);
        expect(node.id).toBe('FGT5004');          // == fightId → autoHydrate tgt.id
        expect(node.fightId).toBe('FGT5004');
        expect(node.architectureSegment).toBe('Core');
        expect(node.tacticIds).toEqual(['TA5001']);
    });
    it('ATLAS: id === atlasId, carries the ATT&CK cross-ref', () => {
        const node = toAtlasTechniqueNode({
            id: 'pg-2', atlasId: 'AML.T0043', name: 'Craft Adversarial Data', description: 'd',
            maturity: 'demonstrated', subtechniqueOf: null, tacticIds: ['AML.TA0002'],
            attackReferenceId: 'T1596', attackReferenceUrl: null, url: null,
            createdAt: now, updatedAt: now,
        } as never);
        expect(node.id).toBe('AML.T0043');
        expect(node.maturity).toBe('demonstrated');
        expect(node.attackReferenceId).toBe('T1596');
    });
    it('truncates long descriptions to 500 chars', () => {
        const node = toFightTechniqueNode({
            id: 'x', fightId: 'FGT1', name: 'x', description: 'a'.repeat(900), bluf: null,
            status: null, architectureSegment: null, typecode: null, tacticIds: null, platforms: null,
            preconditions: null, postconditions: null, criticalAssets: null, detections: null,
            procedureExamples: null, references: null, url: null, createdAt: now, updatedAt: now,
        } as never);
        expect(node.description.length).toBe(500);
    });
});
