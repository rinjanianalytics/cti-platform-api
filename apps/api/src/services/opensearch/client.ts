/**
 * OpenSearch Client — Singleton, Config, Health, Index Management
 */

import { Client } from '@opensearch-project/opensearch';
import { EMBEDDING_DIMENSION } from '../embedding';
import { createLogger } from '../../lib/logger';

const log = createLogger('OpenSearch');

// ============================================================================
// Configuration
// ============================================================================

const OPENSEARCH_URL = process.env.OPENSEARCH_URL || 'http://localhost:9200';
const OPENSEARCH_USERNAME = process.env.OPENSEARCH_USERNAME || 'admin';
const OPENSEARCH_PASSWORD = process.env.OPENSEARCH_PASSWORD || 'admin';

// Index names
export const INDICES = {
    iocs: 'rinjani-iocs',
    vulnerabilities: 'rinjani-vulnerabilities',
    actors: 'rinjani-actors',
    unified: 'rinjani-unified',
};

// ============================================================================
// OpenSearch Client
// ============================================================================

let client: Client | null = null;

export function getOpenSearchClient(): Client {
    if (!client) {
        client = new Client({
            node: OPENSEARCH_URL,
            auth: {
                username: OPENSEARCH_USERNAME,
                password: OPENSEARCH_PASSWORD,
            },
            ssl: {
                rejectUnauthorized: false,
            },
            requestTimeout: 30000,
        });
    }
    return client;
}

// ============================================================================
// Health & Index Management
// ============================================================================

export async function checkHealth(): Promise<{ status: string; indices: string[] }> {
    try {
        const client = getOpenSearchClient();
        const health = await client.cluster.health({});
        const indices = await client.cat.indices({ format: 'json' });

        return {
            status: health.body.status,
            indices: (indices.body as Array<{ index: string }>).map(i => i.index),
        };
    } catch (error) {
        return { status: 'unavailable', indices: [] };
    }
}

export async function createIndices(): Promise<void> {
    const client = getOpenSearchClient();

    const settings = {
        'index.knn': true,
        'index.knn.algo_param.ef_search': 100,
    };

    // Aggregations and term filters across the codebase reference
     // `entityType.keyword`, `severity.keyword`, `source.keyword`, `type.keyword`,
     // and `id.keyword` — keep these multi-fields so the queries resolve.
    const kw = { fields: { keyword: { type: 'keyword' } } };
    const mappings = {
        properties: {
            id: { type: 'keyword', ...kw },
            type: { type: 'keyword', ...kw },
            entityType: { type: 'keyword', ...kw },
            value: { type: 'text', analyzer: 'standard' },
            title: { type: 'text', analyzer: 'standard' },
            description: { type: 'text', analyzer: 'standard' },
            severity: { type: 'keyword', ...kw },
            source: { type: 'keyword', ...kw },
            confidence: { type: 'integer' },
            cvssScore: { type: 'float' },
            tags: { type: 'keyword' },
            createdAt: { type: 'date' },
            updatedAt: { type: 'date' },
            // Vector embedding for semantic search (384-dim, cosine similarity)
            embedding: {
                type: 'knn_vector',
                dimension: EMBEDDING_DIMENSION,
                method: {
                    name: 'hnsw',
                    space_type: 'cosinesimil',
                    engine: 'lucene',
                    parameters: {
                        ef_construction: 128,
                        m: 16,
                    },
                },
            },
        },
    };

    // Create unified index
    try {
        const exists = await client.indices.exists({ index: INDICES.unified });
        if (!exists.body) {
            await client.indices.create({
                index: INDICES.unified,
                body: { settings, mappings },
            });
            log.info('Created index', { index: INDICES.unified });
        }
    } catch (error) {
        log.error('Error creating index', error as Error);
    }
}
