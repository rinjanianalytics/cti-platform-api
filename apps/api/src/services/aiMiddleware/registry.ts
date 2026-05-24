/**
 * AI Middleware — Provider Registry
 *
 * Generative tasks (summarisation, entity extraction, analysis) go through
 * one of: Gemini direct, OpenRouter, or local Ollama. Embeddings are
 * separate and live in `services/embeddingProviders.ts`.
 *
 * Env knobs:
 *   - LLM_PROVIDER         — preferred provider: 'gemini' | 'openrouter' | 'ollama'.
 *                            Falls back through the chain below if unavailable.
 *   - OPENROUTER_MODEL     — override the OpenRouter model. Defaults to a
 *                            free-tier Llama 3.3 70B so you don't burn credits
 *                            in dev. For production, set to the paid variant
 *                            (drop the `:free` suffix) — same model id, no
 *                            quota.
 *   - OLLAMA_MODEL         — override the Ollama model (default `llama3.2`).
 */

import type { LLMProvider, ProviderConfig } from './types';

export function getProviders(): Record<LLMProvider, ProviderConfig> {
    return {
        gemini: {
            name: 'gemini',
            available: !!(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY),
            endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
            apiKey: process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY,
            defaultModel: 'gemini-2.0-flash',
        },
        openrouter: {
            name: 'openrouter',
            available: !!process.env.OPENROUTER_API_KEY,
            endpoint: 'https://openrouter.ai/api/v1/chat/completions',
            apiKey: process.env.OPENROUTER_API_KEY,
            // Llama 3.3 70B Instruct. `:free` variant has 20 req/min, 200 req/day
            // limits — fine for dev. Strip the suffix for paid (unlimited).
            defaultModel: process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.3-70b-instruct:free',
        },
        ollama: {
            name: 'ollama',
            available: true,
            endpoint: process.env.OLLAMA_URL || 'http://localhost:11434/api/generate',
            defaultModel: process.env.OLLAMA_MODEL || 'llama3.2',
        },
    };
}

/**
 * Get the best available provider, honouring an explicit caller preference
 * first, then the LLM_PROVIDER env, then the default fallback chain.
 */
export function selectProvider(preferred?: LLMProvider): ProviderConfig {
    const providers = getProviders();

    // Explicit caller override wins.
    if (preferred && providers[preferred]?.available) {
        return providers[preferred];
    }

    // Env-pinned preference (LLM_PROVIDER=openrouter for the Llama-70B path).
    const envPin = process.env.LLM_PROVIDER as LLMProvider | undefined;
    if (envPin && providers[envPin]?.available) {
        return providers[envPin];
    }

    // Fallback chain: Gemini → OpenRouter → Ollama. Gemini is first because
    // it's the cheapest hosted option when its quota isn't exhausted; the
    // chain decays toward self-hosted as cloud creds run out.
    if (providers.gemini.available) return providers.gemini;
    if (providers.openrouter.available) return providers.openrouter;
    return providers.ollama;
}
