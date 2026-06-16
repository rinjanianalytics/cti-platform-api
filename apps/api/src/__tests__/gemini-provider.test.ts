/**
 * callGemini request-shape tests.
 *
 * Regression guard for the 2026-06-16 production bug: callGemini built its
 * request body WITHOUT the system prompt (OpenRouter and Ollama both forwarded
 * opts.systemPrompt; Gemini silently dropped it). Since Gemini is the primary
 * provider, every Gemini call ran with no system prompt — which is why
 * NL→Cypher's "{"cypher": …}" instruction never reached the model and it
 * returned prose / topic-keyed JSON instead of a query.
 *
 * Also asserts thinkingConfig.thinkingBudget:0 (gemini-2.5-flash reasoning
 * tokens were eating maxOutputTokens and truncating the JSON).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { callGemini } from '../services/aiMiddleware/providers';
import type { ProviderConfig } from '../services/aiMiddleware/types';

const provider: ProviderConfig = {
    name: 'gemini',
    available: true,
    endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
    apiKey: 'test-key',
    defaultModel: 'gemini-flash-latest',
};

function mockFetchOK(text: string) {
    const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
            candidates: [{ content: { parts: [{ text }] } }],
            usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 },
        }),
    });
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
}

/** Pull the parsed JSON request body from the most recent fetch call. */
function lastBody(fetchMock: ReturnType<typeof vi.fn>) {
    const [, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
    return JSON.parse((init as RequestInit).body as string);
}

beforeEach(() => vi.clearAllMocks());
afterEach(() => vi.unstubAllGlobals());

describe('callGemini — request shape', () => {
    it('forwards opts.systemPrompt as systemInstruction (the dropped-prompt bug)', async () => {
        const fetchMock = mockFetchOK('{"cypher": "MATCH (n) RETURN n LIMIT 1"}');
        await callGemini(provider, 'gemini-flash-latest', 'which actors use Emotet?',
            { systemPrompt: 'You translate questions to Cypher. Reply ONLY {"cypher": "..."}.' }, 0);

        const body = lastBody(fetchMock);
        expect(body.systemInstruction).toBeDefined();
        expect(body.systemInstruction.parts[0].text).toContain('Reply ONLY');
        // The user question still rides in contents, separate from the system prompt.
        expect(body.contents[0].parts[0].text).toBe('which actors use Emotet?');
    });

    it('omits systemInstruction entirely when no systemPrompt given', async () => {
        const fetchMock = mockFetchOK('hi');
        await callGemini(provider, 'gemini-flash-latest', 'hello', {}, 0);
        expect(lastBody(fetchMock).systemInstruction).toBeUndefined();
    });

    it('disables thinking so reasoning tokens cannot truncate the answer', async () => {
        const fetchMock = mockFetchOK('ok');
        await callGemini(provider, 'gemini-flash-latest', 'hello', {}, 0);
        expect(lastBody(fetchMock).generationConfig.thinkingConfig).toEqual({ thinkingBudget: 0 });
    });

    it('sets responseMimeType only under jsonMode', async () => {
        const fetchMock = mockFetchOK('{}');
        await callGemini(provider, 'gemini-flash-latest', 'hello', { jsonMode: true }, 0);
        expect(lastBody(fetchMock).generationConfig.responseMimeType).toBe('application/json');

        await callGemini(provider, 'gemini-flash-latest', 'hello', {}, 0);
        expect(lastBody(fetchMock).generationConfig.responseMimeType).toBeUndefined();
    });
});
