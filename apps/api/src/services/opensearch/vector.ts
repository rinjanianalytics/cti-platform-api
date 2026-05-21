/**
 * OpenSearch Vector Search — k-NN Semantic Search + Similarity
 */

import { generateEmbedding } from '../embedding';
import { getOpenSearchClient, INDICES, createIndices } from './client';
import { createLogger } from '../../lib/logger';

const log = createLogger('OpenSearch');

interface OSHit {
    _id: string;
    _score: number | null;
    _source: Record<string, unknown>;
}

// ============================================================================
// Vector Search (k-NN Semantic Search)
// ============================================================================

export interface VectorSearchResult {
    items: Record<string, unknown>[];
    total: number;
    took: number;
}

/**
 * Semantic search using k-NN vector similarity.
 * Generates an embedding from the query text and finds the nearest neighbors.
 */
export async function vectorSearch(
    query: string,
    k: number = 10,
    entityType?: string
): Promise<VectorSearchResult> {
    const client = getOpenSearchClient();

    // Generate query embedding
    const queryEmbedding = await generateEmbedding(query);

    const filter: Record<string, unknown>[] = [];
    if (entityType) {
        filter.push({ term: { 'entityType.keyword': entityType } });
    }

    const searchBody: Record<string, unknown> = {
        size: k,
        query: {
            bool: {
                must: [
                    {
                        knn: {
                            embedding: {
                                vector: queryEmbedding,
                                k,
                            },
                        },
                    },
                ],
                filter,
            },
        },
    };

    try {
        const response = await client.search({
            index: INDICES.unified,
            body: searchBody,
        });

        const hits = response.body.hits;
        const items = hits.hits.map((hit: OSHit) => ({
            _score: hit._score,
            ...hit._source,
            // Don't return embedding vectors to client
            embedding: undefined,
        }));

        return {
            items,
            total: typeof hits.total === 'number' ? hits.total : hits.total?.value || 0,
            took: response.body.took,
        };
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) {
            return { items: [], total: 0, took: 0 };
        }
        throw error;
    }
}

/**
 * Find documents similar to a given document by its OpenSearch ID.
 * Retrieves the document's embedding and finds k nearest neighbors.
 */
export async function findSimilar(
    docId: string,
    k: number = 10,
    entityType?: string
): Promise<VectorSearchResult> {
    const client = getOpenSearchClient();

    // OpenSearch _ids are prefixed (`ioc-<uuid>`, `vuln-<uuid>`, `actor-<uuid>`).
    // Callers usually pass the raw postgres uuid — try that first, then fall
    // back to the entity-prefixed form. Order: plain, ioc-, vuln-, actor-.
    const candidates: string[] = [docId];
    if (!/^(ioc|vuln|actor)-/.test(docId)) {
        if (entityType === 'vulnerability') candidates.push(`vuln-${docId}`);
        else if (entityType === 'threat_actor') candidates.push(`actor-${docId}`);
        else if (entityType === 'ioc') candidates.push(`ioc-${docId}`);
        else candidates.push(`ioc-${docId}`, `vuln-${docId}`, `actor-${docId}`);
    }

    let sourceEmbedding: number[] | undefined;
    for (const id of candidates) {
        try {
            const docResponse = await client.get({ index: INDICES.unified, id });
            sourceEmbedding = docResponse.body._source?.embedding;
            if (sourceEmbedding) break;
        } catch (error) {
            if ((error as { meta?: { statusCode?: number } }).meta?.statusCode !== 404) throw error;
            // fall through to next candidate
        }
    }

    try {
        if (!sourceEmbedding) {
            return { items: [], total: 0, took: 0 };
        }

        const filter: Record<string, unknown>[] = [];
        if (entityType) {
            filter.push({ term: { 'entityType.keyword': entityType } });
        }

        const searchBody: Record<string, unknown> = {
            size: k + 1, // +1 because the source doc will be in results
            query: {
                bool: {
                    must: [
                        {
                            knn: {
                                embedding: {
                                    vector: sourceEmbedding,
                                    k: k + 1,
                                },
                            },
                        },
                    ],
                    filter,
                },
            },
        };

        const response = await client.search({
            index: INDICES.unified,
            body: searchBody,
        });

        const hits = response.body.hits;
        const items = hits.hits
            .filter((hit: OSHit) => hit._id !== docId) // Exclude source document
            .slice(0, k)
            .map((hit: OSHit) => ({
                _score: hit._score,
                ...hit._source,
                embedding: undefined,
            }));

        return {
            items,
            total: items.length,
            took: response.body.took,
        };
    } catch (error) {
        if ((error as { meta?: { statusCode?: number } }).meta?.statusCode === 404) {
            return { items: [], total: 0, took: 0 };
        }
        throw error;
    }
}

/**
 * Delete and recreate the unified index with the new knn_vector mapping.
 * Required when adding vector fields to an existing index.
 */
export async function recreateIndex(): Promise<void> {
    const client = getOpenSearchClient();

    try {
        const exists = await client.indices.exists({ index: INDICES.unified });
        if (exists.body) {
            await client.indices.delete({ index: INDICES.unified });
            log.info('Deleted index', { index: INDICES.unified });
        }
    } catch (error) {
        log.warn('Error deleting index', { error });
    }

    await createIndices();
    log.info('Index recreated with knn_vector mapping');
}
