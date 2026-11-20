import { setTimeout } from 'node:timers/promises';
import { request, type HttpResponse } from './http';
import type { ModelConnection } from './model-settings';

/** Credentials belong only to the explicitly selected connection. */
export function modelHeaders(connection: ModelConnection, key: string | null): Record<string, string> {
  return { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}),
    ...(connection.provider === 'claude' && key ? { 'x-api-key': key, 'anthropic-version': '2023-06-01' } : {}) };
}

/** Keep the chat contract and adapt token controls for OpenAI reasoning models. */
export function modelRequestBody(connection: ModelConnection, body: Record<string, unknown>): string {
  if (connection.provider !== 'openai') return JSON.stringify({ ...body, stream: false });
  const { max_tokens, temperature, ...rest } = body;
  const reasoning = /^(gpt-5|o[134])/.test(String(body.model));
  return JSON.stringify({ ...rest, ...(max_tokens !== undefined ? { max_completion_tokens: max_tokens } : {}),
    ...(!reasoning && temperature !== undefined ? { temperature } : {}), stream: false });
}

export class ModelRequestError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

/** Retry transient errors with warnings, then raise; never switch to another provider. */
export async function modelRequest(connection: ModelConnection, key: string | null, path: string, body: string | null, signal: AbortSignal, timeoutMs: number): Promise<HttpResponse> {
  const url = `${connection.base_url}${path}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await request(url, { method: body === null ? 'GET' : 'POST', headers: modelHeaders(connection, key),
        ...(body === null ? {} : { body }), signal, timeoutMs, maxBytes: 4 * 1024 * 1024,
        destination: { allowPrivate: connection.provider === 'ollama_local' } });
      if (response.ok) return response;
      const detail = key ? response.text().replaceAll(key, '[redacted]') : response.text();
      throw new ModelRequestError(response.status, `${body === null ? 'GET' : 'POST'} ${url} failed for model ${connection.model}: HTTP ${response.status}; response: ${detail.slice(0, 2000)}`);
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      if (signal.aborted || attempt === 3 || (failure instanceof ModelRequestError && failure.status !== 429 && failure.status < 500)) throw failure;
      console.warn('Model provider request failed; retrying', { provider: connection.provider, model: connection.model, url, attempt, status: failure instanceof ModelRequestError ? failure.status : null, error: failure.message });
      await setTimeout(200 * 2 ** (attempt - 1), undefined, { signal });
    }
  }
}
