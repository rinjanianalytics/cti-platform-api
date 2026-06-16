/**
 * NL→Cypher safety guard + extractor tests.
 *
 * These are the lines of defense between user input and the Neo4j
 * driver; they MUST be tight.
 */
import { describe, it, expect } from 'vitest';
import { isReadOnlyCypher, __testing } from '../services/nlCypher';
import { NlCypherSchema } from '../lib/schemas';

const { extractCypher } = __testing;

describe('isReadOnlyCypher — accepts', () => {
    it('a plain MATCH ... RETURN', () => {
        expect(isReadOnlyCypher(`MATCH (a:Actor)-[:USES]->(m:Malware) RETURN a.name, m.name LIMIT 25`).ok).toBe(true);
    });

    it('a query starting with a `//` comment', () => {
        expect(isReadOnlyCypher(`// list APT28 malware\nMATCH (a:Actor {name:'APT28'})-[:USES]->(m:Malware) RETURN m LIMIT 10`).ok).toBe(true);
    });

    it('a property name that contains a write-keyword substring (DELETED_AT)', () => {
        // No word-boundary write keyword in this property name → must pass.
        expect(isReadOnlyCypher(`MATCH (n:IOC) WHERE n.deletedAt IS NULL RETURN n LIMIT 5`).ok).toBe(true);
    });

    it('a query using COUNT aggregation without LIMIT', () => {
        expect(isReadOnlyCypher(`MATCH (n:Actor) RETURN count(n)`).ok).toBe(true);
    });
});

describe('isReadOnlyCypher — rejects', () => {
    it('an explicit CREATE', () => {
        const r = isReadOnlyCypher(`CREATE (n:Actor {name:'evil'}) RETURN n`);
        expect(r.ok).toBe(false);
    });

    it('a sneaky MERGE inside a MATCH ... RETURN', () => {
        const r = isReadOnlyCypher(`MATCH (a:Actor) MERGE (a)-[:USES]->(m:Malware) RETURN a`);
        expect(r.ok).toBe(false);
    });

    it('a SET on a matched node', () => {
        const r = isReadOnlyCypher(`MATCH (n) SET n.evil=true RETURN n`);
        expect(r.ok).toBe(false);
    });

    it('a DELETE', () => {
        expect(isReadOnlyCypher(`MATCH (n) DELETE n`).ok).toBe(false);
    });

    it('a DETACH DELETE', () => {
        expect(isReadOnlyCypher(`MATCH (n) DETACH DELETE n`).ok).toBe(false);
    });

    it('a REMOVE property', () => {
        expect(isReadOnlyCypher(`MATCH (n) REMOVE n.tag RETURN n`).ok).toBe(false);
    });

    it('a DROP CONSTRAINT', () => {
        expect(isReadOnlyCypher(`DROP CONSTRAINT actor_unique`).ok).toBe(false);
    });

    it('a CALL apoc.create.relationship procedure', () => {
        const r = isReadOnlyCypher(`MATCH (a),(b) CALL apoc.create.relationship(a,'X',{},b) YIELD rel RETURN rel`);
        expect(r.ok).toBe(false);
    });

    it('a CALL dbms.security procedure', () => {
        const r = isReadOnlyCypher(`CALL dbms.security.createUser('bad','pwd')`);
        expect(r.ok).toBe(false);
    });

    it('an empty string', () => {
        expect(isReadOnlyCypher('').ok).toBe(false);
    });

    it('the LLM "unanswerable" sentinel', () => {
        expect(isReadOnlyCypher('// unanswerable').ok).toBe(false);
    });

    it('a query without MATCH or RETURN', () => {
        expect(isReadOnlyCypher(`WITH 1 AS x`).ok).toBe(false);
    });
});

describe('extractCypher', () => {
    it('strips a ```cypher fence', () => {
        const raw = '```cypher\nMATCH (n) RETURN n LIMIT 5\n```';
        expect(extractCypher(raw)).toBe('MATCH (n) RETURN n LIMIT 5');
    });

    it('strips a plain ``` fence', () => {
        expect(extractCypher('```\nMATCH (n) RETURN n\n```')).toBe('MATCH (n) RETURN n');
    });

    it('strips a "Cypher:" prose prefix', () => {
        expect(extractCypher('Cypher: MATCH (n) RETURN n')).toBe('MATCH (n) RETURN n');
    });

    it('strips a "Here is the query:" prose prefix', () => {
        expect(extractCypher('Here is the query: MATCH (n) RETURN n')).toBe('MATCH (n) RETURN n');
    });

    it('leaves a clean query untouched', () => {
        expect(extractCypher('MATCH (n) RETURN n LIMIT 25')).toBe('MATCH (n) RETURN n LIMIT 25');
    });
});

describe('NlCypherSchema', () => {
    it('requires a non-empty question', () => {
        expect(() => NlCypherSchema.parse({ question: '' })).toThrow();
    });

    it('defaults limit to 25', () => {
        const r = NlCypherSchema.parse({ question: 'show me apt28 malware' });
        expect(r.limit).toBe(25);
    });

    it('coerces string limit', () => {
        expect(NlCypherSchema.parse({ question: 'x', limit: '50' }).limit).toBe(50);
    });

    it('caps limit at 500', () => {
        expect(() => NlCypherSchema.parse({ question: 'x', limit: 1000 })).toThrow();
    });

    it('rejects unknown provider', () => {
        expect(() => NlCypherSchema.parse({ question: 'x', provider: 'gpt-4' })).toThrow();
    });
});

describe('NL→Cypher knows the telco subgraph (B1.5)', () => {
    const prompt = __testing.SYSTEM_PROMPT;

    it('includes the three telco node labels so the LLM can target them', () => {
        expect(prompt).toContain('NetworkElement');
        expect(prompt).toContain('SignalingInterface');
        expect(prompt).toContain('FraudScheme');
    });

    it('includes the four telco edge types (SCREAMING_SNAKE_CASE matches cypherEdgeLabel)', () => {
        for (const edge of ['CONNECTS_TO', 'USES_INTERFACE', 'ENABLES_FRAUD', 'EXPLOITS_VIA']) {
            expect(prompt).toContain(edge);
        }
    });

    it('documents telco node properties the operator would query on', () => {
        expect(prompt).toContain('elementType');         // network element type
        expect(prompt).toContain('gsmaFsCategories');    // fraud scheme GSMA mapping
        expect(prompt).toContain('protocol');            // signaling interface
    });

    it('read-only guard still rejects writes against a telco label (regression)', () => {
        const r = isReadOnlyCypher(`MATCH (f:FraudScheme) MERGE (f)-[:USES_INTERFACE]->(s:SignalingInterface) RETURN f`);
        expect(r.ok).toBe(false);
    });

    it('accepts a read-only telco hunt query', () => {
        const q = `MATCH (f:FraudScheme {schemeType:'sim-swap'})-[:EXPLOITS_VIA]->(s:SignalingInterface) RETURN f.name, s.protocol LIMIT 25`;
        expect(isReadOnlyCypher(q).ok).toBe(true);
    });
});

describe('extractCypher — structured {"cypher": ...} output (B-fix: prose adherence)', () => {
    const { extractCypher } = __testing as unknown as { extractCypher: (s: string) => string };

    it('parses the cypher field from a JSON object', () => {
        const out = extractCypher('{"cypher": "MATCH (a:Actor) RETURN a LIMIT 25"}');
        expect(out).toBe('MATCH (a:Actor) RETURN a LIMIT 25');
    });

    it('strips a ```json fence around the object', () => {
        const out = extractCypher('```json\n{"cypher": "MATCH (n:IOC) RETURN n LIMIT 5"}\n```');
        expect(out).toBe('MATCH (n:IOC) RETURN n LIMIT 5');
    });

    it('passes the // unanswerable sentinel through', () => {
        expect(extractCypher('{"cypher": "// unanswerable"}')).toBe('// unanswerable');
    });

    it('falls back to plain Cypher when the model ignores jsonMode', () => {
        expect(extractCypher('MATCH (f:FraudScheme) RETURN f LIMIT 25'))
            .toBe('MATCH (f:FraudScheme) RETURN f LIMIT 25');
    });

    it('falls back to label-stripping for "Cypher:"-prefixed plain text', () => {
        expect(extractCypher('Cypher: MATCH (n) RETURN n LIMIT 1')).toBe('MATCH (n) RETURN n LIMIT 1');
    });

    it('a prose answer (no cypher field, no query) yields non-Cypher text that isReadOnlyCypher rejects', () => {
        // This is the exact prod failure: gemini returned a prose paragraph.
        // With jsonMode it should not happen, but if a provider regresses, the
        // safety guard still catches it downstream.
        const out = extractCypher('In mobile telecommunications, Diameter is the AAA protocol.');
        expect(isReadOnlyCypher(out).ok).toBe(false);
    });

    // ---- prod 2026-06-16: gemini-flash-latest ignored jsonMode two ways ----

    it('PROD run-1: preamble before a fenced JSON block — finds the cypher field anyway', () => {
        // Observed verbatim: "Here is the JSON requested:\n```json\n{...}\n```".
        // The old extractor only stripped a fence at the very START, so the
        // preamble survived and isReadOnlyCypher rejected it ("no MATCH").
        const raw = 'Here is the JSON requested:\n```json\n{"cypher": "MATCH (f:FraudScheme)-[:EXPLOITS_VIA]->(s:SignalingInterface) WHERE s.protocol = \'Diameter\' RETURN f.name LIMIT 25"}\n```';
        const out = extractCypher(raw);
        expect(out).toBe("MATCH (f:FraudScheme)-[:EXPLOITS_VIA]->(s:SignalingInterface) WHERE s.protocol = 'Diameter' RETURN f.name LIMIT 25");
        expect(isReadOnlyCypher(out).ok).toBe(true);
    });

    it('PROD run-2: truncated JSON (cut at maxTokens) — salvages the raw MATCH', () => {
        // Observed verbatim cypher fragment: '{\n  "diameter…' — JSON.parse
        // fails on the truncated object, so the salvage path grabs from MATCH.
        const raw = 'Some preamble.\n{\n  "cypher": "MATCH (f:FraudScheme)-[:EXPLOITS_VIA]->(s:SignalingInterface) RETURN f.name LIMIT 25';
        const out = extractCypher(raw);
        expect(out.startsWith('MATCH (f:FraudScheme)')).toBe(true);
        expect(isReadOnlyCypher(out).ok).toBe(true);
    });

    it('finds the cypher field even with a leading prose preamble (no fence)', () => {
        const out = extractCypher('Sure! {"cypher": "MATCH (n:IOC) RETURN n LIMIT 5"} hope that helps');
        expect(out).toBe('MATCH (n:IOC) RETURN n LIMIT 5');
    });

    it('salvages a raw OPTIONAL MATCH query buried after prose, dropping a trailing fence', () => {
        const out = extractCypher('Here you go:\nMATCH (a:Actor) RETURN a LIMIT 25\n```');
        expect(out).toBe('MATCH (a:Actor) RETURN a LIMIT 25');
    });
});

describe('SYSTEM_PROMPT requests structured JSON output', () => {
    it('instructs the model to return {"cypher": ...}', () => {
        expect(__testing.SYSTEM_PROMPT).toContain('"cypher"');
        expect(__testing.SYSTEM_PROMPT).toMatch(/Do NOT answer the question in words/i);
    });
});
