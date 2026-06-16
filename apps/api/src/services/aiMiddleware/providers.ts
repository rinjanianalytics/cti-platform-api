/**
 * AI Middleware — Provider Implementations
 */

import type { LLMOptions, LLMResponse, ProviderConfig } from './types';

export async function callGemini(
    provider: ProviderConfig, model: string, prompt: string, opts: LLMOptions, start: number,
): Promise<LLMResponse> {
    const url = `${provider.endpoint}/${model}:generateContent?key=${provider.apiKey}`;

    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            // systemInstruction is Gemini v1beta's field for the system prompt.
            // It was MISSING — OpenRouter (system role) and Ollama (body.system)
            // both forward opts.systemPrompt, but Gemini silently dropped it, so
            // every Gemini call ran without its system prompt (schema docs,
            // output-format rules, etc.). That's why NL→Cypher's "{"cypher": …}"
            // instruction never took: the model only saw the bare question.
            ...(opts.systemPrompt && {
                systemInstruction: { parts: [{ text: opts.systemPrompt }] },
            }),
            generationConfig: {
                temperature: opts.temperature ?? 0.3,
                maxOutputTokens: opts.maxTokens ?? 4096,
                ...(opts.jsonMode && { responseMimeType: 'application/json' }),
                // gemini-flash-latest resolves to gemini-2.5-flash, whose
                // thinking tokens count against maxOutputTokens — a low cap
                // (e.g. NL→Cypher's 700) got consumed by reasoning before any
                // answer was emitted, truncating the JSON mid-object. Cypher
                // generation is deterministic; we don't want chain-of-thought.
                // thinkingBudget:0 disables it (supported on 2.5-flash/-lite).
                thinkingConfig: { thinkingBudget: 0 },
            },
        }),
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Gemini ${res.status}: ${errText.slice(0, 200)}`);
    }

    const data = await res.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const tokensUsed = (data.usageMetadata?.promptTokenCount || 0) +
        (data.usageMetadata?.candidatesTokenCount || 0);

    return { text, provider: 'gemini', model, tokensUsed, latencyMs: Date.now() - start };
}

export async function callOpenRouter(
    provider: ProviderConfig, model: string, prompt: string, opts: LLMOptions, start: number,
): Promise<LLMResponse> {
    const messages: Array<{ role: string; content: string }> = [];

    if (opts.systemPrompt) {
        messages.push({ role: 'system', content: opts.systemPrompt });
    }
    messages.push({ role: 'user', content: prompt });

    const body: Record<string, unknown> = {
        model,
        messages,
        temperature: opts.temperature ?? 0.3,
        max_tokens: opts.maxTokens ?? 4096,
    };

    if (opts.jsonMode) {
        body.response_format = { type: 'json_object' };
    }

    const res = await fetch(provider.endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${provider.apiKey}`,
            'HTTP-Referer': 'https://rinjani.ai',
            'X-Title': 'RinjaniCTI',
        },
        body: JSON.stringify(body),
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`OpenRouter ${res.status}: ${errText.slice(0, 200)}`);
    }

    const data = await res.json();
    const text = data.choices?.[0]?.message?.content || '';
    const tokensUsed = data.usage?.total_tokens || 0;

    return { text, provider: 'openrouter', model, tokensUsed, latencyMs: Date.now() - start };
}

export async function callOllama(
    provider: ProviderConfig, model: string, prompt: string, opts: LLMOptions, start: number,
): Promise<LLMResponse> {
    const body: Record<string, unknown> = {
        model,
        prompt,
        stream: false,
        options: {
            temperature: opts.temperature ?? 0.3,
            num_predict: opts.maxTokens ?? 4096,
        },
    };

    if (opts.jsonMode) {
        body.format = 'json';
    }

    if (opts.systemPrompt) {
        body.system = opts.systemPrompt;
    }

    const res = await fetch(provider.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60000),
    });

    if (!res.ok) {
        throw new Error(`Ollama ${res.status}`);
    }

    const data = await res.json();
    return {
        text: data.response || '',
        provider: 'ollama',
        model,
        latencyMs: Date.now() - start,
    };
}
