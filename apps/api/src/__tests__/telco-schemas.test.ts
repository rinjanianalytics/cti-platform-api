/**
 * Unit tests for the B1.1 /v1/telco request-body schemas.
 *
 * Pure zod validation (project convention — service-layer DB ops verified by
 * curl round-trip, not a unit harness). Covers the three telco entity bodies:
 * network elements, signaling interfaces, fraud schemes.
 */

import { describe, expect, it } from 'vitest';
import { __schemas } from '../routes/v1/telco';

const { NetworkElementBody, SignalingInterfaceBody, FraudSchemeBody } = __schemas;

describe('NetworkElementBody', () => {
    it('accepts a full network element', () => {
        const r = NetworkElementBody.safeParse({
            refId: 'ericsson:hss:core',
            name: 'Ericsson HSS (Core)',
            elementType: 'HSS',
            architectureSegment: 'Core',
            vendor: ['Ericsson'],
            interfaces: [{ name: 'S6a', protocol: 'Diameter' }],
        });
        expect(r.success).toBe(true);
        if (r.success) {
            // defaults applied
            expect(r.data.externalReferences).toEqual([]);
            expect(r.data.labels).toEqual([]);
        }
    });

    it('requires refId, name, elementType', () => {
        expect(NetworkElementBody.safeParse({ name: 'x', elementType: 'HSS' }).success).toBe(false); // no refId
        expect(NetworkElementBody.safeParse({ refId: 'a', elementType: 'HSS' }).success).toBe(false); // no name
        expect(NetworkElementBody.safeParse({ refId: 'a', name: 'x' }).success).toBe(false);          // no elementType
    });

    it('rejects refId / name over the DB varchar limits', () => {
        expect(NetworkElementBody.safeParse({ refId: 'a'.repeat(256), name: 'x', elementType: 'HSS' }).success).toBe(false);
        expect(NetworkElementBody.safeParse({ refId: 'a', name: 'x'.repeat(501), elementType: 'HSS' }).success).toBe(false);
    });

    it('stixId is optional (telco entities are not STIX objects)', () => {
        const r = NetworkElementBody.safeParse({ refId: 'a', name: 'x', elementType: 'HSS' });
        expect(r.success).toBe(true);
        if (r.success) expect(r.data.stixId).toBeUndefined();
    });

    it('accepts an explicit stixId when provided', () => {
        const r = NetworkElementBody.safeParse({ refId: 'a', name: 'x', elementType: 'HSS', stixId: 'x-telco--1' });
        expect(r.success).toBe(true);
    });
});

describe('SignalingInterfaceBody', () => {
    it('accepts a full signaling interface', () => {
        const r = SignalingInterfaceBody.safeParse({
            refId: 'diameter:s6a',
            name: 'S6a (HSS↔MME)',
            protocol: 'Diameter',
            referencePoint: 'S6a',
            specRef: '3GPP TS 29.272',
        });
        expect(r.success).toBe(true);
    });

    it('requires refId, name, protocol', () => {
        expect(SignalingInterfaceBody.safeParse({ name: 'x', protocol: 'SS7' }).success).toBe(false);
        expect(SignalingInterfaceBody.safeParse({ refId: 'a', name: 'x' }).success).toBe(false); // no protocol
    });

    it('referencePoint + specRef are optional', () => {
        const r = SignalingInterfaceBody.safeParse({ refId: 'gtp:s11', name: 'S11', protocol: 'GTP' });
        expect(r.success).toBe(true);
    });
});

describe('FraudSchemeBody', () => {
    it('accepts a full fraud scheme with GSMA categories', () => {
        const r = FraudSchemeBody.safeParse({
            refId: 'sim-swap:port-out',
            name: 'SIM-swap (port-out)',
            schemeType: 'sim-swap',
            monetization: 'account takeover → bank drain',
            gsmaFsCategories: ['FS.11'],
        });
        expect(r.success).toBe(true);
        if (r.success) expect(r.data.gsmaFsCategories).toEqual(['FS.11']);
    });

    it('requires refId, name, schemeType', () => {
        expect(FraudSchemeBody.safeParse({ name: 'x', schemeType: 'irsf' }).success).toBe(false);
        expect(FraudSchemeBody.safeParse({ refId: 'a', name: 'x' }).success).toBe(false); // no schemeType
    });

    it('gsmaFsCategories defaults to [] (populated/queried in B1.3)', () => {
        const r = FraudSchemeBody.safeParse({ refId: 'irsf:premium', name: 'IRSF', schemeType: 'irsf' });
        expect(r.success).toBe(true);
        if (r.success) expect(r.data.gsmaFsCategories).toEqual([]);
    });
});
