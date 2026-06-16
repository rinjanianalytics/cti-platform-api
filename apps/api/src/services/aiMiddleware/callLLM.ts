/**
 * AI Middleware — Core LLM Router
 *
 * Tries each available provider AT MOST ONCE, in a deterministic order
 * (explicit preference first, then the Gemini → OpenRouter → Ollama
 * cascade), and throws a single aggregated error if all fail.
 *
 * The previous implementation recursed on failure — `provider:'openrouter'`
 * fell back to `provider:undefined`, which re-selected Gemini, which fell
 * back to OpenRouter, … an INFINITE loop that hung the request and hammered
 * every provider (each iteration fired real HTTP calls; observed in prod as a
 * Gemini↔OpenRouter ping-pong storm on 2026-06-16). The bounded, linear chain
 * below is the fix: at most one attempt per provider, then a clean
 * `All LLM providers failed` error the caller can surface or degrade on.
 */

import { createLogger } from '../../lib/logger';
import type { LLMOptions, LLMProvider, LLMResponse } from './types';
import { getProviders } from './registry';
import { callGemini, callOpenRouter, callOllama } from './providers';

const log = createLogger('AI:MW');

/** Default cascade when no explicit provider is requested. */
const FALLBACK_ORDER: LLMProvider[] = ['gemini', 'openrouter', 'ollama'];

/**
 * Unified LLM call. Routes to the first available provider that succeeds.
 * Never recurses — each provider is attempted at most once.
 */
export async function callLLM(prompt: string, opts: LLMOptions = {}): Promise<LLMResponse> {
    const providers = getProviders();

    // Build the ordered, de-duplicated candidate chain: explicit preference
    // first (incl. the LLM_PROVIDER env pin), then the default cascade.
    const envPin = process.env.LLM_PROVIDER as LLMProvider | undefined;
    const ordered: LLMProvider[] = [];
    for (const p of [opts.provider, envPin, ...FALLBACK_ORDER]) {
        if (p && !ordered.includes(p)) ordered.push(p);
    }
    // Only providers that are actually configured/available.
    const candidates = ordered.filter((p) => providers[p]?.available);

    if (candidates.length === 0) {
        throw new Error('No LLM provider is available (set GEMINI_API_KEY / OPENROUTER_API_KEY, or run Ollama)');
    }

    const errors: string[] = [];
    for (const name of candidates) {
        const provider = providers[name];
        // Honour an explicit opts.model ONLY for the explicitly-requested
        // provider — a Gemini model name must not leak onto an OpenRouter call.
        const model = (opts.model && name === opts.provider) ? opts.model : provider.defaultModel;
        const start = Date.now();

        log.info('LLM call', { provider: name, model, promptPreview: prompt.slice(0, 80) });

        try {
            switch (name) {
                case 'gemini':
                    return await callGemini(provider, model, prompt, opts, start);
                case 'openrouter':
                    return await callOpenRouter(provider, model, prompt, opts, start);
                case 'ollama':
                    return await callOllama(provider, model, prompt, opts, start);
                default:
                    continue;
            }
        } catch (err) {
            const msg = (err as Error).message;
            errors.push(`${name}: ${msg}`);
            // Always log WHY a provider failed (the old code dropped the
            // Gemini error on the floor, hiding key/quota problems).
            log.warn('LLM provider failed, trying next', { provider: name, error: msg });
        }
    }

    throw new Error(`All LLM providers failed [${candidates.join(' → ')}] — ${errors.join(' | ')}`);
}
