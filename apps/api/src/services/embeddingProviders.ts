/**
 * Cloud Embedding Providers
 *
 * REST API implementations for OpenAI, OpenRouter, and Gemini embedding APIs.
 * All providers output 384-dim vectors to match the OpenSearch knn_vector index.
 *
 * No SDK dependencies — uses native fetch().
 */

import { getConfig } from './configStore';
import { createLogger } from '../lib/logger';

const log = createLogger('EmbeddingProvider');

const TARGET_DIM = 384;

// ============================================================================
// Provider Interface
// ============================================================================

export type EmbeddingProviderName = 'local' | 'openai' | 'openrouter' | 'gemini';

export interface EmbeddingProviderConfig {
    name: EmbeddingProviderName;
    model: string;
    apiKeyEnv: string;           // env var / config key for the API key
    maxBatchSize: number;
}

export const PROVIDER_CONFIGS: Record<Exclude<EmbeddingProviderName, 'local'>, EmbeddingProviderConfig> = {
    openai: {
        name: 'openai',
        model: 'text-embedding-3-small',
        apiKeyEnv: 'OPENAI_API_KEY',
        maxBatchSize: 2048,      // OpenAI supports up to 2048 inputs
    },
    openrouter: {
        name: 'openrouter',
        model: 'openai/text-embedding-3-small',
        apiKeyEnv: 'OPENROUTER_API_KEY',
        maxBatchSize: 2048,
    },
    gemini: {
        name: 'gemini',
        // gemini-embedding-001 is the current production model on the v1 API.
        // (text-embedding-004 only exists on v1beta and returns 404 on v1.)
        model: 'gemini-embedding-001',
        apiKeyEnv: 'GEMINI_API_KEY',
        maxBatchSize: 100,       // Gemini has smaller batch limits
    },
};

// ============================================================================
// API Key Resolution
// ============================================================================

async function getApiKey(envKey: string): Promise<string | null> {
    // Try config store first (set via dashboard), then env var
    return await getConfig(envKey) || process.env[envKey] || null;
}

// ============================================================================
// OpenAI / OpenRouter (same API shape)
// ============================================================================

async function openaiEmbed(
    texts: string[],
    config: EmbeddingProviderConfig,
    baseUrl: string,
): Promise<number[][]> {
    const apiKey = await getApiKey(config.apiKeyEnv);
    if (!apiKey) throw new Error(`${config.name} API key not configured (${config.apiKeyEnv})`);

    const results: number[][] = [];

    // Batch in chunks respecting provider limits
    for (let i = 0; i < texts.length; i += config.maxBatchSize) {
        const batch = texts.slice(i, i + config.maxBatchSize);

        const res = await fetch(`${baseUrl}/v1/embeddings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
                ...(config.name === 'openrouter' ? { 'HTTP-Referer': 'https://rinjani.analytics' } : {}),
            },
            body: JSON.stringify({
                model: config.model,
                input: batch,
                dimensions: TARGET_DIM,  // OpenAI text-embedding-3-* supports custom dims
            }),
        });

        if (!res.ok) {
            const err = await res.text().catch(() => 'Unknown error');
            throw new Error(`${config.name} embedding API error ${res.status}: ${err}`);
        }

        const data = await res.json() as {
            data: Array<{ embedding: number[]; index: number }>;
        };

        // Sort by index to ensure correct ordering
        const sorted = data.data.sort((a, b) => a.index - b.index);
        for (const item of sorted) {
            results.push(item.embedding.slice(0, TARGET_DIM));
        }
    }

    return results;
}

export async function openaiGenerateEmbedding(text: string): Promise<number[]> {
    const config = PROVIDER_CONFIGS.openai;
    const [result] = await openaiEmbed([text], config, 'https://api.openai.com');
    return result;
}

export async function openaiGenerateBatchEmbeddings(texts: string[]): Promise<number[][]> {
    const config = PROVIDER_CONFIGS.openai;
    return openaiEmbed(texts, config, 'https://api.openai.com');
}

export async function openrouterGenerateEmbedding(text: string): Promise<number[]> {
    const config = PROVIDER_CONFIGS.openrouter;
    const [result] = await openaiEmbed([text], config, 'https://openrouter.ai/api');
    return result;
}

export async function openrouterGenerateBatchEmbeddings(texts: string[]): Promise<number[][]> {
    const config = PROVIDER_CONFIGS.openrouter;
    return openaiEmbed(texts, config, 'https://openrouter.ai/api');
}

// ============================================================================
// Gemini
// ============================================================================

export async function geminiGenerateEmbedding(text: string): Promise<number[]> {
    const config = PROVIDER_CONFIGS.gemini;
    const apiKey = await getApiKey(config.apiKeyEnv);
    if (!apiKey) throw new Error(`Gemini API key not configured (${config.apiKeyEnv})`);

    const url = `https://generativelanguage.googleapis.com/v1/models/${config.model}:embedContent?key=${apiKey}`;
    const MAX_RETRIES = 3;

    let lastError: Error | null = null;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: `models/${config.model}`,
                    content: { parts: [{ text }] },
                    outputDimensionality: TARGET_DIM,
                }),
            });

            if (res.ok) {
                const data = await res.json() as { embedding: { values: number[] } };
                return data.embedding.values.slice(0, TARGET_DIM);
            }

            // 4xx (except 429) is permanent — fail fast with a short message.
            if (res.status >= 400 && res.status < 500 && res.status !== 429) {
                const err = await res.text().catch(() => '');
                throw new Error(`Gemini embedding API error ${res.status}: ${err.slice(0, 200)}`);
            }

            // 429 / 5xx — transient. Back off and retry.
            const waitMs = Math.min(1000 * Math.pow(2, attempt), 8000);
            log.warn('Gemini embedding transient error — retrying', {
                status: res.status, attempt: attempt + 1, waitMs,
            });
            await new Promise(r => setTimeout(r, waitMs));
            lastError = new Error(`Gemini embedding API error ${res.status}`);
        } catch (err) {
            // Network error / abort — also retry.
            lastError = err as Error;
            if (attempt < MAX_RETRIES - 1) {
                const waitMs = Math.min(1000 * Math.pow(2, attempt), 8000);
                log.warn('Gemini embedding network error — retrying', {
                    error: lastError.message, attempt: attempt + 1, waitMs,
                });
                await new Promise(r => setTimeout(r, waitMs));
            }
        }
    }

    // Out of retries — surface a SHORT error (no HTML body in the log).
    throw new Error(`Gemini embedding failed after ${MAX_RETRIES} attempts: ${lastError?.message ?? 'unknown'}`);
}

export async function geminiGenerateBatchEmbeddings(texts: string[]): Promise<number[][]> {
    const config = PROVIDER_CONFIGS.gemini;
    const apiKey = await getApiKey(config.apiKeyEnv);
    if (!apiKey) throw new Error(`Gemini API key not configured (${config.apiKeyEnv})`);

    const results: number[][] = [];
    const MAX_RETRIES = 3;

    // Gemini batchEmbedContents endpoint
    for (let i = 0; i < texts.length; i += config.maxBatchSize) {
        const batch = texts.slice(i, i + config.maxBatchSize);

        const url = `https://generativelanguage.googleapis.com/v1/models/${config.model}:batchEmbedContents?key=${apiKey}`;

        let lastError: Error | null = null;
        let success = false;

        for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
            try {
                const res = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        requests: batch.map(text => ({
                            model: `models/${config.model}`,
                            content: { parts: [{ text }] },
                            outputDimensionality: TARGET_DIM,
                        })),
                    }),
                });

                if (res.status === 429 || res.status === 503) {
                    // Rate limited or overloaded — exponential backoff
                    const waitMs = Math.min(1000 * Math.pow(2, attempt), 8000);
                    log.warn('Gemini rate limited, retrying', {
                        status: res.status, attempt: attempt + 1, waitMs, batchStart: i,
                    });
                    await new Promise(r => setTimeout(r, waitMs));
                    continue;
                }

                if (!res.ok) {
                    const err = await res.text().catch(() => 'Unknown error');
                    const msg = `Gemini batch embedding API error ${res.status}: ${err}`;
                    // 4xx errors (except 429) are permanent — don't retry
                    if (res.status >= 400 && res.status < 500) {
                        throw new Error(msg);
                    }
                    // 5xx (except 503) — retry with backoff
                    const waitMs = Math.min(1000 * Math.pow(2, attempt), 8000);
                    log.warn('Gemini embedding error, retrying', { error: msg, attempt: attempt + 1, waitMs });
                    lastError = new Error(msg);
                    await new Promise(r => setTimeout(r, waitMs));
                    continue;
                }

                const data = await res.json() as {
                    embeddings: Array<{ values: number[] }>;
                };

                for (const emb of data.embeddings) {
                    results.push(emb.values.slice(0, TARGET_DIM));
                }

                success = true;
                break;
            } catch (err) {
                lastError = err instanceof Error ? err : new Error(String(err));
                if (attempt < MAX_RETRIES - 1) {
                    const waitMs = Math.min(1000 * Math.pow(2, attempt), 8000);
                    log.warn('Gemini embedding error, retrying', {
                        error: lastError.message, attempt: attempt + 1, waitMs,
                    });
                    await new Promise(r => setTimeout(r, waitMs));
                }
            }
        }

        if (!success) {
            log.error('Gemini embedding failed after retries', {
                error: lastError?.message, batchStart: i, batchSize: batch.length,
            });
            throw lastError || new Error('Gemini embedding failed');
        }

        // Small delay between batches to avoid rate limiting
        if (i + config.maxBatchSize < texts.length) {
            await new Promise(r => setTimeout(r, 50));
        }
    }

    return results;
}

// ============================================================================
// Provider Resolution
// ============================================================================

export async function getActiveProvider(): Promise<EmbeddingProviderName> {
    const provider = await getConfig('EMBEDDING_PROVIDER');
    if (provider && ['local', 'openai', 'openrouter', 'gemini'].includes(provider)) {
        return provider as EmbeddingProviderName;
    }
    return 'local';
}

/**
 * Get the display model name for the active provider.
 */
export function getProviderModel(provider: EmbeddingProviderName): string {
    if (provider === 'local') return 'Xenova/all-MiniLM-L6-v2';
    return PROVIDER_CONFIGS[provider].model;
}

/**
 * Check if a provider's API key is configured.
 */
export async function isProviderConfigured(provider: EmbeddingProviderName): Promise<boolean> {
    if (provider === 'local') return true;
    const key = await getApiKey(PROVIDER_CONFIGS[provider].apiKeyEnv);
    return key !== null && key.length > 0;
}
