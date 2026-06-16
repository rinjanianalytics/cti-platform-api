/**
 * callLLM fallback-chain tests.
 *
 * Regression guard for the 2026-06-16 production bug: the old recursive
 * fallback (openrouter → undefined → gemini → openrouter → …) looped
 * INFINITELY when Gemini failed and OpenRouter was rate-limited, hanging the
 * request and hammering both providers. The "all providers fail" test below
 * would HANG (vitest timeout) if that regressed — it asserts a clean throw
 * instead, with at most one attempt per provider.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/aiMiddleware/registry', () => ({
    getProviders: vi.fn(),
}));
vi.mock('../services/aiMiddleware/providers', () => ({
    callGemini: vi.fn(),
    callOpenRouter: vi.fn(),
    callOllama: vi.fn(),
}));

import { callLLM } from '../services/aiMiddleware/callLLM';
import { getProviders } from '../services/aiMiddleware/registry';
import { callGemini, callOpenRouter, callOllama } from '../services/aiMiddleware/providers';

const cfg = (available: boolean, defaultModel: string) => ({
    name: '', available, endpoint: 'http://x', defaultModel,
});

function allAvailable() {
    vi.mocked(getProviders).mockReturnValue({
        gemini: { ...cfg(true, 'gemini-2.0-flash'), name: 'gemini' },
        openrouter: { ...cfg(true, 'meta-llama/llama-3.3-70b-instruct:free'), name: 'openrouter' },
        ollama: { ...cfg(true, 'llama3.2'), name: 'ollama' },
    });
}

const ok = (provider: string) => ({ text: `from-${provider}`, provider, model: 'm', latencyMs: 1 });

beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.LLM_PROVIDER;
});
afterEach(() => vi.resetAllMocks());

describe('callLLM — happy paths', () => {
    it('returns the first provider (gemini) when it succeeds; no fallback', async () => {
        allAvailable();
        vi.mocked(callGemini).mockResolvedValue(ok('gemini') as never);
        const r = await callLLM('hi');
        expect(r.text).toBe('from-gemini');
        expect(callOpenRouter).not.toHaveBeenCalled();
        expect(callOllama).not.toHaveBeenCalled();
    });

    it('falls through gemini → openrouter when gemini fails', async () => {
        allAvailable();
        vi.mocked(callGemini).mockRejectedValue(new Error('gemini 401'));
        vi.mocked(callOpenRouter).mockResolvedValue(ok('openrouter') as never);
        const r = await callLLM('hi');
        expect(r.text).toBe('from-openrouter');
        expect(callGemini).toHaveBeenCalledTimes(1);    // exactly once — no loop
        expect(callOpenRouter).toHaveBeenCalledTimes(1);
    });

    it('falls all the way to ollama when gemini + openrouter fail', async () => {
        allAvailable();
        vi.mocked(callGemini).mockRejectedValue(new Error('gemini 401'));
        vi.mocked(callOpenRouter).mockRejectedValue(new Error('OpenRouter 429'));
        vi.mocked(callOllama).mockResolvedValue(ok('ollama') as never);
        const r = await callLLM('hi');
        expect(r.text).toBe('from-ollama');
    });
});

describe('callLLM — THE regression: all providers fail must THROW, not loop', () => {
    it('throws a single aggregated error after one attempt each (would hang if it looped)', async () => {
        allAvailable();
        vi.mocked(callGemini).mockRejectedValue(new Error('gemini 401'));
        vi.mocked(callOpenRouter).mockRejectedValue(new Error('OpenRouter 429'));
        vi.mocked(callOllama).mockRejectedValue(new Error('ECONNREFUSED'));

        await expect(callLLM('hi')).rejects.toThrow(/All LLM providers failed/);

        // The crux: each provider attempted EXACTLY once. The old recursive
        // code would have called these dozens of times before (never) settling.
        expect(callGemini).toHaveBeenCalledTimes(1);
        expect(callOpenRouter).toHaveBeenCalledTimes(1);
        expect(callOllama).toHaveBeenCalledTimes(1);
    });

    it('aggregated error includes each provider reason (visibility — old code hid gemini)', async () => {
        allAvailable();
        vi.mocked(callGemini).mockRejectedValue(new Error('gemini 401 invalid key'));
        vi.mocked(callOpenRouter).mockRejectedValue(new Error('OpenRouter 429'));
        vi.mocked(callOllama).mockRejectedValue(new Error('ECONNREFUSED'));
        await expect(callLLM('hi')).rejects.toThrow(/gemini 401 invalid key.*OpenRouter 429/s);
    });
});

describe('callLLM — provider selection', () => {
    it('honours an explicit provider first, then falls back', async () => {
        allAvailable();
        vi.mocked(callOpenRouter).mockRejectedValue(new Error('429'));
        vi.mocked(callGemini).mockResolvedValue(ok('gemini') as never);
        const r = await callLLM('hi', { provider: 'openrouter' });
        // openrouter tried first (explicit), failed, then gemini.
        expect(r.text).toBe('from-gemini');
        expect(vi.mocked(callOpenRouter).mock.invocationCallOrder[0])
            .toBeLessThan(vi.mocked(callGemini).mock.invocationCallOrder[0]);
    });

    it('skips unavailable providers (no key) and never calls them', async () => {
        vi.mocked(getProviders).mockReturnValue({
            gemini: { ...cfg(false, 'gemini-2.0-flash'), name: 'gemini' },        // no key
            openrouter: { ...cfg(true, 'llama'), name: 'openrouter' },
            ollama: { ...cfg(false, 'llama3.2'), name: 'ollama' },                 // not running
        });
        vi.mocked(callOpenRouter).mockResolvedValue(ok('openrouter') as never);
        const r = await callLLM('hi');
        expect(r.text).toBe('from-openrouter');
        expect(callGemini).not.toHaveBeenCalled();
        expect(callOllama).not.toHaveBeenCalled();
    });

    it('throws a clear error when NO provider is available', async () => {
        vi.mocked(getProviders).mockReturnValue({
            gemini: { ...cfg(false, 'g'), name: 'gemini' },
            openrouter: { ...cfg(false, 'o'), name: 'openrouter' },
            ollama: { ...cfg(false, 'l'), name: 'ollama' },
        });
        await expect(callLLM('hi')).rejects.toThrow(/No LLM provider is available/);
    });

    it('does not leak an explicit opts.model onto a fallback provider', async () => {
        allAvailable();
        vi.mocked(callGemini).mockRejectedValue(new Error('boom'));
        vi.mocked(callOpenRouter).mockResolvedValue(ok('openrouter') as never);
        await callLLM('hi', { provider: 'gemini', model: 'gemini-custom-model' });
        // gemini got the custom model; openrouter got ITS default, not the gemini name.
        expect(vi.mocked(callGemini).mock.calls[0][1]).toBe('gemini-custom-model');
        expect(vi.mocked(callOpenRouter).mock.calls[0][1]).toBe('meta-llama/llama-3.3-70b-instruct:free');
    });
});
