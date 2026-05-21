/**
 * OpenSearch Indexing — Bulk & Single Document Indexing
 *
 * Handles indexing IOCs, Vulnerabilities, Actors with vector embeddings.
 */

import { db } from '@rinjani/db';
import { iocs, vulnerabilities, threatActors } from '@rinjani/db/schema';
import type { IOC, Vulnerability } from '@rinjani/db/schema';
import {
    generateEmbedding,
    generateBatchEmbeddings,
    getIOCEmbeddingText,
    getVulnerabilityEmbeddingText,
    getActorEmbeddingText,
} from '../embedding';
import { getOpenSearchClient, INDICES, createIndices } from './client';
import { createLogger } from '../../lib/logger';

const log = createLogger('OpenSearch');

// ============================================================================
// Reindex Progress Tracking (in-memory, read by /ops/embedding endpoint)
// ============================================================================

const reindexProgress = {
    active: false,
    phase: 'idle' as 'idle' | 'iocs' | 'vulnerabilities' | 'actors',
    processed: 0,
    total: 0,
    startedAt: null as string | null,
};

export function getReindexProgress() {
    return {
        ...reindexProgress,
        percent: reindexProgress.total > 0
            ? Math.round((reindexProgress.processed / reindexProgress.total) * 100)
            : 0,
    };
}

// ============================================================================
// Helpers — Fetch Existing Embeddings from OpenSearch
// ============================================================================

/**
 * Fetch existing embeddings from OpenSearch for a set of document IDs.
 * Returns a Map of docId -> embedding vector.
 * This avoids regenerating embeddings for documents that already have them.
 */
async function fetchExistingEmbeddings(docIds: string[]): Promise<Map<string, number[]>> {
    const client = getOpenSearchClient();
    const result = new Map<string, number[]>();
    if (docIds.length === 0) return result;

    try {
        const response = await client.mget({
            index: INDICES.unified,
            body: {
                ids: docIds,
            },
            _source_includes: ['embedding'],
        });

        const docs = (response.body?.docs || []) as Array<{
            _id: string;
            found: boolean;
            _source?: { embedding?: number[] };
        }>;

        for (const doc of docs) {
            if (doc.found && doc._source?.embedding && doc._source.embedding.length > 0) {
                result.set(doc._id, doc._source.embedding);
            }
        }
    } catch {
        // If mget fails (index doesn't exist yet), return empty — all docs need embedding
    }

    return result;
}

// ============================================================================
// Indexing Functions - Bulk (for full reindex)
// ============================================================================

export async function indexIOCs(): Promise<number> {
    const client = getOpenSearchClient();
    // No limit - index all IOCs
    const items = await db.select().from(iocs);

    if (items.length === 0) return 0;

    // Track progress
    reindexProgress.phase = 'iocs';
    reindexProgress.processed = 0;
    reindexProgress.total = items.length;

    // Batch in chunks of 500 (smaller for embedding generation)
    const chunkSize = 500;
    let indexed = 0;

    for (let i = 0; i < items.length; i += chunkSize) {
        const chunk = items.slice(i, i + chunkSize);
        const docs = chunk.map((item) => mapIOCToDocument(item));
        const docIds = docs.map((d) => `ioc-${d.id}`);

        // Fetch existing embeddings from OpenSearch to avoid regenerating
        const existing = await fetchExistingEmbeddings(docIds);
        const needEmbedding: number[] = [];
        const needTexts: string[] = [];

        for (let j = 0; j < docs.length; j++) {
            if (!existing.has(docIds[j])) {
                needEmbedding.push(j);
                needTexts.push(getIOCEmbeddingText(docs[j]));
            }
        }

        // Only generate embeddings for docs that don't have them yet
        let newEmbeddings: number[][] = [];
        if (needTexts.length > 0) {
            try {
                newEmbeddings = await generateBatchEmbeddings(needTexts);
            } catch (err) {
                log.warn('Embedding generation failed for IOC chunk, indexing without vectors', {
                    chunk: i,
                    error: err instanceof Error ? err.message : String(err),
                });
            }
        }

        // Merge: existing embeddings + newly generated ones
        const body = docs.flatMap((doc, idx) => {
            const id = docIds[idx];
            let emb = existing.get(id);
            if (!emb) {
                const newIdx = needEmbedding.indexOf(idx);
                emb = newIdx >= 0 ? newEmbeddings[newIdx] : undefined;
            }
            return [
                { index: { _index: INDICES.unified, _id: id } },
                { ...doc, embedding: emb || undefined },
            ];
        });
        await client.bulk({ body, refresh: false });
        indexed += chunk.length;
        reindexProgress.processed = indexed;

        const skipped = docs.length - needTexts.length;
        if (i % 2000 === 0) {
            log.info('IOCs indexed', {
                indexed: Math.min(indexed, items.length), total: items.length,
                embeddingsReused: skipped, embeddingsGenerated: needTexts.length,
            });
        }

        // Yield event loop between chunks so API stays responsive
        await new Promise<void>(resolve => setImmediate(resolve));
    }

    await client.indices.refresh({ index: INDICES.unified });
    return indexed;
}

export async function indexVulnerabilities(): Promise<number> {
    const client = getOpenSearchClient();
    // No limit - index all vulnerabilities
    const items = await db.select().from(vulnerabilities);

    if (items.length === 0) return 0;

    // Track progress
    reindexProgress.phase = 'vulnerabilities';
    reindexProgress.processed = 0;
    reindexProgress.total = items.length;

    const chunkSize = 500;
    let indexed = 0;

    for (let i = 0; i < items.length; i += chunkSize) {
        const chunk = items.slice(i, i + chunkSize);
        const docs = chunk.map((item) => mapVulnerabilityToDocument(item));
        const docIds = docs.map((d) => `vuln-${d.id}`);

        const existing = await fetchExistingEmbeddings(docIds);
        const needEmbedding: number[] = [];
        const needTexts: string[] = [];

        for (let j = 0; j < docs.length; j++) {
            if (!existing.has(docIds[j])) {
                needEmbedding.push(j);
                needTexts.push(getVulnerabilityEmbeddingText(docs[j]));
            }
        }

        let newEmbeddings: number[][] = [];
        if (needTexts.length > 0) {
            try {
                newEmbeddings = await generateBatchEmbeddings(needTexts);
            } catch (err) {
                log.warn('Embedding generation failed for vuln chunk, indexing without vectors', {
                    chunk: i,
                    error: err instanceof Error ? err.message : String(err),
                });
            }
        }

        const body = docs.flatMap((doc, idx) => {
            const id = docIds[idx];
            let emb = existing.get(id);
            if (!emb) {
                const newIdx = needEmbedding.indexOf(idx);
                emb = newIdx >= 0 ? newEmbeddings[newIdx] : undefined;
            }
            return [
                { index: { _index: INDICES.unified, _id: id } },
                { ...doc, embedding: emb || undefined },
            ];
        });
        await client.bulk({ body, refresh: false });
        indexed += chunk.length;
        reindexProgress.processed = indexed;

        const skipped = docs.length - needTexts.length;
        if (i % 2000 === 0) {
            log.info('Vulns indexed', {
                indexed: Math.min(indexed, items.length), total: items.length,
                embeddingsReused: skipped, embeddingsGenerated: needTexts.length,
            });
        }

        await new Promise<void>(resolve => setImmediate(resolve));
    }

    await client.indices.refresh({ index: INDICES.unified });
    return indexed;
}

export async function indexActors(): Promise<number> {
    const client = getOpenSearchClient();
    const items = await db.select().from(threatActors);

    if (items.length === 0) return 0;

    // Track progress
    reindexProgress.phase = 'actors';
    reindexProgress.processed = 0;
    reindexProgress.total = items.length;

    const docs = items.map((item) => mapActorToDocument(item));
    const docIds = docs.map((d) => `actor-${d.id}`);

    const existing = await fetchExistingEmbeddings(docIds);
    const needEmbedding: number[] = [];
    const needTexts: string[] = [];

    for (let j = 0; j < docs.length; j++) {
        if (!existing.has(docIds[j])) {
            needEmbedding.push(j);
            needTexts.push(getActorEmbeddingText(docs[j]));
        }
    }

    let newEmbeddings: number[][] = [];
    if (needTexts.length > 0) {
        try {
            newEmbeddings = await generateBatchEmbeddings(needTexts);
        } catch (err) {
            log.warn('Embedding generation failed for actors, indexing without vectors', {
                error: err instanceof Error ? err.message : String(err),
            });
        }
    }

    log.info('Actors embedding stats', {
        total: docs.length, reused: existing.size, generated: needTexts.length,
    });

    const body = docs.flatMap((doc, idx) => {
        const id = docIds[idx];
        let emb = existing.get(id);
        if (!emb) {
            const newIdx = needEmbedding.indexOf(idx);
            emb = newIdx >= 0 ? newEmbeddings[newIdx] : undefined;
        }
        return [
            { index: { _index: INDICES.unified, _id: id } },
            { ...doc, embedding: emb || undefined },
        ];
    });

    await client.bulk({ body, refresh: true });
    return items.length;
}

// ============================================================================
// Severity Derivation from CVSS Score
// ============================================================================

function deriveSeverityFromCvss(cvssScore: unknown): string | null {
    const score = typeof cvssScore === 'number' ? cvssScore : parseFloat(String(cvssScore));
    if (isNaN(score) || score < 0) return null;
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
}

// ============================================================================
// Document Mapping Helpers
// ============================================================================

export function mapIOCToDocument(item: Record<string, unknown>) {
    return {
        id: item.id,
        entityType: 'ioc',
        type: item.type,
        value: item.value,
        title: item.value,
        description: item.threatType || '',
        severity: item.severity || 'medium',
        source: item.source,
        confidence: item.confidence,
        tags: item.tags || [],
        // Full 1:1 mapping with PostgreSQL iocs table
        stixId: item.stixId || null,
        threatType: item.threatType || null,
        pattern: item.pattern || null,
        patternType: item.patternType || null,
        indicator: item.indicator || null,
        validFrom: item.validFrom || null,
        validUntil: item.validUntil || null,
        killChainPhases: item.killChainPhases || [],
        externalReferences: item.externalReferences || [],
        labels: item.labels || [],
        firstSeen: item.firstSeen,
        lastSeen: item.lastSeen,
        createdAt: item.createdAt || item.firstSeen,
        updatedAt: item.updatedAt || item.lastSeen,
    };
}

export function mapVulnerabilityToDocument(item: Record<string, unknown>) {
    return {
        id: item.id,
        entityType: 'vulnerability',
        type: 'cve',
        value: item.cveId,
        title: item.cveId,
        description: item.description || '',
        severity: (() => {
            const raw = typeof item.severity === 'string' ? item.severity.toLowerCase() : null;
            // Treat 'none' and empty as missing — fall through to derivation
            if (raw && raw !== 'none' && raw !== 'unknown') return raw;
            return deriveSeverityFromCvss(item.cvssScore) || 'medium';
        })(),
        source: 'nvd',
        cvssScore: item.cvssScore,
        cvssVector: item.cvssVector || null,
        vendorProject: item.vendorProject || null,
        product: item.product || null,
        isExploited: item.isExploited || false,
        exploitedAt: item.exploitedAt || null,
        stixId: item.stixId || null,
        tags: [],
        createdAt: item.publishedDate,
        updatedAt: item.lastModified || item.updatedAt,
        publishedDate: item.publishedDate,
    };
}

export function mapActorToDocument(item: Record<string, unknown>) {
    return {
        id: item.id,
        entityType: 'threat-actor',
        type: 'threat-actor',
        value: item.name,
        title: item.name,
        description: item.description || '',
        severity: 'high',
        source: String(item.stixId || '').startsWith('misp-galaxy--') ? 'mispgalaxy' : 'mitre',
        tags: item.aliases || [],
        // Full 1:1 mapping with PostgreSQL threat_actors table
        stixId: item.stixId || null,
        aliases: item.aliases || [],
        sophistication: item.sophistication || null,
        resourceLevel: item.resourceLevel || null,
        primaryMotivation: item.primaryMotivation || null,
        secondaryMotivations: item.secondaryMotivations || [],
        goals: item.goals || [],
        labels: item.labels || [],
        externalReferences: item.externalReferences || [],
        // Postgres stores STIX enum string (none/low/medium/high) for actors but
        // the OpenSearch unified index types `confidence` as integer (IOCs use
        // 0-100). Normalise to integer at the indexing boundary so both forms
        // coexist without the mapper_parsing_exception.
        confidence: confidenceToInteger(item.confidence),
        createdByRef: item.createdByRef || null,
        objectMarkingRefs: item.objectMarkingRefs || [],
        stixCreated: item.stixCreated || null,
        stixModified: item.stixModified || null,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
    };
}

/**
 * Normalise actor confidence (STIX enum or 0-100 integer string) to a
 * 0-100 integer for OpenSearch. Buckets match the LLM enrichment
 * thresholds: high=90, medium=60, low=30, none=0.
 *
 * Returns null when input is null/empty so the index entry stays clean.
 */
function confidenceToInteger(raw: unknown): number | null {
    if (raw == null || raw === '') return null;
    if (typeof raw === 'number') {
        if (!Number.isFinite(raw)) return null;
        const pct = raw <= 1 && raw > 0 ? raw * 100 : raw;
        return Math.max(0, Math.min(100, Math.round(pct)));
    }
    if (typeof raw === 'string') {
        const norm = raw.toLowerCase().trim();
        switch (norm) {
            case 'high': case 'very-high': case 'critical': return 90;
            case 'medium': case 'moderate': case 'mid': return 60;
            case 'low': case 'minimal': case 'very-low': return 30;
            case 'none': return 0;
            default: {
                const n = Number(norm);
                if (!Number.isFinite(n)) return null;
                const pct = n <= 1 && n > 0 ? n * 100 : n;
                return Math.max(0, Math.min(100, Math.round(pct)));
            }
        }
    }
    return null;
}

// ============================================================================
// Single-Document Indexing (for real-time sync)
// ============================================================================

export async function indexSingleIOC(item: Record<string, unknown>): Promise<void> {
    const client = getOpenSearchClient();
    const doc = mapIOCToDocument(item);
    let embedding: number[] | undefined;
    try {
        embedding = await generateEmbedding(getIOCEmbeddingText(doc));
    } catch (err) {
        log.warn('Embedding failed for IOC', { id: item.id, error: (err as Error)?.message });
    }
    await client.index({
        index: INDICES.unified,
        id: `ioc-${item.id}`,
        body: { ...doc, embedding },
        refresh: true,
    });
}

export async function indexSingleVulnerability(item: Record<string, unknown>): Promise<void> {
    const client = getOpenSearchClient();
    const doc = mapVulnerabilityToDocument(item);
    let embedding: number[] | undefined;
    try {
        embedding = await generateEmbedding(getVulnerabilityEmbeddingText(doc));
    } catch (err) {
        log.warn('Embedding failed for vuln', { id: item.id, error: (err as Error)?.message });
    }
    await client.index({
        index: INDICES.unified,
        id: `vuln-${item.id}`,
        body: { ...doc, embedding },
        refresh: true,
    });
}

export async function indexSingleActor(item: Record<string, unknown>): Promise<void> {
    const client = getOpenSearchClient();
    const doc = mapActorToDocument(item);
    let embedding: number[] | undefined;
    try {
        embedding = await generateEmbedding(getActorEmbeddingText(doc));
    } catch (err) {
        log.warn('Embedding failed for actor', { id: item.id, error: (err as Error)?.message });
    }
    await client.index({
        index: INDICES.unified,
        id: `actor-${item.id}`,
        body: { ...doc, embedding },
        refresh: true,
    });
}

export async function deleteDocument(entityType: string, id: string): Promise<void> {
    const client = getOpenSearchClient();
    const docId = `${entityType}-${id}`;
    try {
        await client.delete({
            index: INDICES.unified,
            id: docId,
            refresh: true,
        });
    } catch (error) {
        // Ignore 404 errors (document doesn't exist)
        if ((error as { statusCode?: number }).statusCode !== 404) throw error;
    }
}

export async function reindexAll(): Promise<{ iocs: number; vulnerabilities: number; actors: number }> {
    await createIndices();

    reindexProgress.active = true;
    reindexProgress.startedAt = new Date().toISOString();

    try {
        const iocCount = await indexIOCs();
        const vulnCount = await indexVulnerabilities();
        const actorCount = await indexActors();

        return {
            iocs: iocCount,
            vulnerabilities: vulnCount,
            actors: actorCount,
        };
    } finally {
        reindexProgress.active = false;
        reindexProgress.phase = 'idle';
    }
}
