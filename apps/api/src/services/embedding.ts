/**
 * Embedding Service
 *
 * Multi-provider embedding generation:
 *   - Local: @xenova/transformers with all-MiniLM-L6-v2 (384-dim, ~22MB, CPU)
 *   - Cloud: OpenAI, OpenRouter, Gemini via REST APIs
 *
 * Provider is selected via EMBEDDING_PROVIDER setting in the config store.
 * All providers output 384-dim vectors for OpenSearch compatibility.
 */

// @ts-ignore — @xenova/transformers uses dynamic imports
import { pipeline, env } from '@xenova/transformers';
import { createLogger } from '../lib/logger';
import { getConfig } from './configStore';
import {
    getActiveProvider,
    openaiGenerateEmbedding, openaiGenerateBatchEmbeddings,
    openrouterGenerateEmbedding, openrouterGenerateBatchEmbeddings,
    geminiGenerateEmbedding, geminiGenerateBatchEmbeddings,
} from './embeddingProviders';

const log = createLogger('Embedding');

// Pipeline type from @xenova/transformers (no exported type available)
type TransformersPipeline = Awaited<ReturnType<typeof pipeline>>;

// ============================================================================
// Configuration
// ============================================================================

// Disable remote model downloads after first load (models cached locally)
env.allowLocalModels = true;
env.allowRemoteModels = true; // Allow first download, then cached

// The library's default cache is a folder inside its own package directory.
// In the Docker image that directory belongs to root and the API runs as a
// non-root user, so the write fails and the model is downloaded again on
// every start. EMBEDDING_CACHE_DIR points the cache at a writable folder.
if (process.env.EMBEDDING_CACHE_DIR) {
    env.cacheDir = process.env.EMBEDDING_CACHE_DIR;
}

const MODEL_NAME = 'Xenova/all-MiniLM-L6-v2';
const EMBEDDING_DIM = 384;
const BATCH_SIZE = 32; // Process embeddings in batches

// ============================================================================
// Progress Tracking (in-memory, read by /ops/embedding endpoint)
// ============================================================================

const embeddingProgress = {
    active: false,
    processed: 0,
    total: 0,
    phase: 'idle' as string,
    startedAt: null as string | null,
};

export function getEmbeddingProgress() {
    return {
        ...embeddingProgress,
        percent: embeddingProgress.total > 0
            ? Math.round((embeddingProgress.processed / embeddingProgress.total) * 100)
            : 0,
    };
}

// ============================================================================
// Singleton Pipeline
// ============================================================================

let embeddingPipeline: TransformersPipeline | null = null;
let pipelineLoading: Promise<TransformersPipeline> | null = null;

/**
 * Get or initialize the embedding pipeline (singleton).
 * First call downloads the model (~22MB), subsequent calls return cached.
 */
async function getEmbeddingPipeline() {
    if (embeddingPipeline) return embeddingPipeline;

    if (!pipelineLoading) {
        pipelineLoading = (async () => {
            log.info('Loading model', { model: MODEL_NAME });
            const start = Date.now();
            embeddingPipeline = await pipeline('feature-extraction', MODEL_NAME, {
                quantized: true, // Use quantized model for faster inference
            });
            log.info('Model loaded', { model: MODEL_NAME, durationMs: Date.now() - start });
            return embeddingPipeline;
        })();
    }

    return pipelineLoading;
}

// ============================================================================
// Embedding Generation
// ============================================================================

/**
 * Generate a 384-dim embedding vector from text.
 * Dispatches to the active provider (local, openai, openrouter, gemini).
 */
export async function generateEmbedding(text: string): Promise<number[]> {
    // Check if embedding is disabled via dashboard toggle
    const enabled = await getConfig('AI_ANALYSIS_ENABLED');
    if (enabled === 'false') {
        return []; // Return empty vector — document will be indexed without embedding
    }

    const provider = await getActiveProvider();

    // Cloud providers
    switch (provider) {
        case 'openai': return openaiGenerateEmbedding(text);
        case 'openrouter': return openrouterGenerateEmbedding(text);
        case 'gemini': return geminiGenerateEmbedding(text);
    }

    // Local (Xenova) — default
    const pipe = await getEmbeddingPipeline();
    const truncated = text.slice(0, 512);
    // @ts-expect-error — Xenova types don't narrow for feature-extraction pipeline; pooling/normalize are valid at runtime
    const output = await pipe(truncated, { pooling: 'mean', normalize: true });
    return Array.from((output as { data: Float32Array }).data).slice(0, EMBEDDING_DIM);
}

/**
 * Generate embeddings for multiple texts in batches.
 * More efficient than calling generateEmbedding() in a loop.
 */
export async function generateBatchEmbeddings(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];

    // Check if embedding is disabled via dashboard toggle
    const enabled = await getConfig('AI_ANALYSIS_ENABLED');
    if (enabled === 'false') {
        log.info('Embedding disabled via settings, skipping batch', { count: texts.length });
        return [];
    }

    const provider = await getActiveProvider();

    // Cloud providers — delegate batching to the provider
    if (provider !== 'local') {
        log.info('Using cloud embedding provider', { provider, count: texts.length });
        switch (provider) {
            case 'openai': return openaiGenerateBatchEmbeddings(texts);
            case 'openrouter': return openrouterGenerateBatchEmbeddings(texts);
            case 'gemini': return geminiGenerateBatchEmbeddings(texts);
        }
    }

    // Local (Xenova) — original batch processing with progress tracking

    const pipe = await getEmbeddingPipeline();
    const results: number[][] = [];

    // Track progress
    embeddingProgress.active = true;
    embeddingProgress.processed = 0;
    embeddingProgress.total = texts.length;
    embeddingProgress.phase = 'generating';
    embeddingProgress.startedAt = new Date().toISOString();

    // Helper to yield the event loop so HTTP requests aren't starved
    const yieldEventLoop = () => new Promise<void>(resolve => setImmediate(resolve));

    try {
        for (let i = 0; i < texts.length; i += BATCH_SIZE) {
            const batch = texts.slice(i, i + BATCH_SIZE).map(t => t.slice(0, 512));

            // Process batch
            for (const text of batch) {
                const output = await pipe(text, {
                    pooling: 'mean',
                    // @ts-expect-error — Xenova types don't include normalize for feature-extraction pipeline but it is valid at runtime
                    normalize: true,
                });
                results.push(Array.from((output as { data: Float32Array }).data).slice(0, EMBEDDING_DIM));

                // Update progress & yield event loop
                embeddingProgress.processed = results.length;
                await yieldEventLoop();
            }

            // Log progress for large batches
            if (texts.length > 100 && i % 500 === 0) {
                log.info('Batch progress', { processed: Math.min(i + BATCH_SIZE, texts.length), total: texts.length });
            }

            // Extra yield between batch groups
            await yieldEventLoop();
        }
    } finally {
        embeddingProgress.active = false;
        embeddingProgress.phase = 'idle';
    }

    return results;
}

// ============================================================================
// Entity Text Builders
// ============================================================================

/**
 * Build embedding text from an IOC document.
 * Combines type, value, severity, source, and description for semantic richness.
 */
export function getIOCEmbeddingText(doc: Record<string, unknown>): string {
    const parts = [
        doc.type || '',
        doc.value || '',
        doc.severity || '',
        doc.source || '',
        doc.description || doc.threatType || '',
        ...(Array.isArray(doc.tags) ? doc.tags as string[] : []),
    ].filter(Boolean);

    return parts.join(' ');
}

/**
 * Build embedding text from a vulnerability/CVE document.
 */
export function getVulnerabilityEmbeddingText(doc: Record<string, unknown>): string {
    const parts = [
        doc.cveId || doc.value || '',
        doc.severity || '',
        doc.description || '',
        doc.vendorProject || '',
        doc.product || '',
    ].filter(Boolean);

    return parts.join(' ');
}

/**
 * Build embedding text from a threat actor document.
 */
export function getActorEmbeddingText(doc: Record<string, unknown>): string {
    const parts = [
        doc.name || doc.value || '',
        ...(Array.isArray(doc.aliases) ? doc.aliases as string[] : []),
        doc.description || '',
        doc.sophistication || '',
        doc.primaryMotivation || '',
        ...(Array.isArray(doc.goals) ? doc.goals as string[] : []),
    ].filter(Boolean);

    return parts.join(' ');
}

/**
 * Get embedding text for any entity based on its type.
 */
export function getEntityEmbeddingText(doc: Record<string, unknown>, entityType: string): string {
    switch (entityType) {
        case 'ioc': return getIOCEmbeddingText(doc);
        case 'vulnerability': return getVulnerabilityEmbeddingText(doc);
        case 'threat-actor': return getActorEmbeddingText(doc);
        default: return `${doc.title || doc.value || ''} ${doc.description || ''}`.trim();
    }
}

// ============================================================================
// Exports
// ============================================================================

export const EMBEDDING_DIMENSION = EMBEDDING_DIM;
