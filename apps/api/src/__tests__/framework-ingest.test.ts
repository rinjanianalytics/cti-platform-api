/**
 * FW.2 ingest tests — the TS port of seed-atlas.py / seed-fight.py.
 *
 * Feeds sample upstream YAML through the ingesters with mocked fetch + db and
 * asserts the field→column mapping (the porting risk). DB is drizzle (typed),
 * so we only verify the values handed to insert().
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { dbMock, captured } = vi.hoisted(() => {
    const captured: Array<{ table: string; v: Record<string, unknown> }> = [];
    const values = (table: string) => (v: Record<string, unknown>) => {
        captured.push({ table, v });
        return { onConflictDoUpdate: () => ({ returning: async () => [{ id: 'actor-1' }] }) };
    };
    return {
        captured,
        dbMock: {
            insert: (t: { __t: string }) => ({ values: values(t.__t) }),
            delete: () => Promise.resolve(),
        },
    };
});
vi.mock('@rinjani/db', () => ({ db: dbMock, eq: (...a: unknown[]) => ({ _eq: a }) }));
vi.mock('@rinjani/db/schema', () => ({
    atlasTactics: { __t: 'atlas_tactics', atlasId: 'atlas_id' },
    atlasTechniques: { __t: 'atlas_techniques', atlasId: 'atlas_id' },
    atlasMitigations: { __t: 'atlas_mitigations', atlasId: 'atlas_id' },
    atlasCaseStudies: { __t: 'atlas_case_studies', atlasId: 'atlas_id' },
    fightTactics: { __t: 'fight_tactics', mitreId: 'mitre_id' },
    fightTechniques: { __t: 'fight_techniques', fightId: 'fight_id' },
    fightMitigations: { __t: 'fight_mitigations', fightId: 'fight_id' },
    fightGroupTechniques: { __t: 'fight_group_techniques' },
    threatActors: { __t: 'threat_actors', stixId: 'stix_id', id: 'id' },
}));

import { ingestAtlas, ingestFight, __testing } from '../services/frameworkIngest';

function stubYaml(text: string) {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, text: async () => text })));
}
const find = (table: string, pred: (v: Record<string, unknown>) => boolean) =>
    captured.find((c) => c.table === table && pred(c.v))?.v;

beforeEach(() => { captured.length = 0; vi.clearAllMocks(); });
afterEach(() => vi.unstubAllGlobals());

describe('ids() normalizes {id} objects and bare strings', () => {
    it('handles both shapes', () => {
        expect(__testing.ids([{ id: 'A' }, 'B', { id: '' }, 123])).toEqual(['A', 'B', '123']);
    });
});

describe('ingestAtlas maps the YAML shape', () => {
    const ATLAS = `
name: ATLAS
version: 5.6.0
matrices:
  - tactics:
      - { id: AML.TA0002, name: Reconnaissance, description: recon, "ATT&CK-reference": { id: TA0043, url: 'http://x' } }
    techniques:
      - { id: AML.T0000, name: Search, description: d, maturity: demonstrated, "subtechnique-of": null, tactics: ['AML.TA0002'], "ATT&CK-reference": { id: T1596, url: 'http://y' } }
    mitigations:
      - { id: AML.M0000, name: Limit, description: d, techniques: [{ id: AML.T0000, use: u }], "ml-lifecycle": ['ML Eng'], category: ['Technical'] }
case-studies:
  - { id: AML.CS0000, name: Case, summary: s, "incident-date": '2020-01', procedure: [{ tactic: AML.TA0002, technique: AML.T0000, description: step }], references: [{ url: 'http://z', title: T }] }
`;
    it('maps technique attribution + tactics + ATT&CK cross-ref', async () => {
        stubYaml(ATLAS);
        const res = await ingestAtlas();
        expect(res).toEqual({ tactics: 1, techniques: 1, mitigations: 1, caseStudies: 1 });
        const tech = find('atlas_techniques', (v) => v.atlasId === 'AML.T0000')!;
        expect(tech.tacticIds).toEqual(['AML.TA0002']);
        expect(tech.attackReferenceId).toBe('T1596');
        expect(tech.maturity).toBe('demonstrated');
        const mit = find('atlas_mitigations', (v) => v.atlasId === 'AML.M0000')!;
        expect(mit.techniqueIds).toEqual(['AML.T0000']); // {id,use} → id
        const cs = find('atlas_case_studies', (v) => v.atlasId === 'AML.CS0000')!;
        expect(cs.techniqueIds).toEqual(['AML.T0000']);  // pulled from procedure steps
    });
});

describe('ingestFight maps the YAML shape', () => {
    const FIGHT = `
tactics:
  - { id: TA5001, name: Fraud, description: d, "short-name": fraud }
techniques:
  - { id: FGT5004, name: SIM-swap, description: d, status: observed, "architecture-segment": Core, tactics: ['TA5001'], addendums: [{ platforms: ['5G Core'] }] }
mitigations:
  - { id: FGM5001, name: M, description: d, techniques: ['FGT5004'] }
groups:
  - { id: FG0001, name: Grp, description: d, aliases: ['G'], techniques: [{ id: FGT5004, name: SIM-swap, use: 'uses it' }] }
`;
    it('maps technique segment/status/addendum-platforms + groups→actors+edges', async () => {
        stubYaml(FIGHT);
        const res = await ingestFight();
        expect(res).toEqual({ tactics: 1, techniques: 1, mitigations: 1, groups: 1, groupTechniques: 1 });
        const tech = find('fight_techniques', (v) => v.fightId === 'FGT5004')!;
        expect(tech.architectureSegment).toBe('Core');
        expect(tech.status).toBe('observed');
        expect(tech.platforms).toEqual(['5G Core']);        // lifted from addendums
        expect(tech.tacticIds).toEqual(['TA5001']);
        const actor = find('threat_actors', (v) => v.stixId === 'fight--FG0001')!;
        expect(actor.primaryMotivation).toBe('telco-targeting');
        const gt = find('fight_group_techniques', (v) => v.fightTechniqueId === 'FGT5004')!;
        expect(gt.groupId).toBe('actor-1');                  // resolved threat_actor id
        expect(gt.description).toBe('uses it');
    });
});
