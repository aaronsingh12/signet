import { env, request, type HttpResponse } from '@signet/core';

// The single cloud LLM adapter (Rulebook v0.2, RB-PROV-01). Everything provider-specific lives here,
// behind this interface, so a second provider later changes this file and the catalogue, not the rules.
// Default target: gpt-oss:120b-cloud via the Ollama OpenAI-compatible endpoint.

const BASE_URL = env('SIGNET_LLM_BASE_URL', 'http://localhost:11434/v1').replace(/\/$/, '');
const TIMEOUT_MS = Number(env('SIGNET_LLM_TIMEOUT_MS', '120000'));

// The provider is down or overloaded: RB-PROV-05 outage behaviour, never a strike.
export class UpstreamUnavailable extends Error {}

// The provider refused the request itself (bad parameters); passed back to the agent.
export class UpstreamRejected extends Error {
  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(`upstream rejected the request (${status})`);
  }
}

export interface ChatResponse {
  id?: string;
  model?: string;
  choices?: {
    index: number;
    finish_reason?: string;
    message: { role: string; content: string | null; reasoning?: string; tool_calls?: { id: string; type: string; function: { name: string; arguments: string } }[] };
  }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
  [k: string]: unknown;
}

export function credentialAttached() {
  return Boolean(process.env.SIGNET_LLM_API_KEY) || BASE_URL.includes('localhost') || BASE_URL.includes('127.0.0.1');
}

export async function chatCompletion(body: Record<string, unknown>, signal: AbortSignal): Promise<ChatResponse> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  // Credential injection (BP 5.2 step 11): the brokered key is added here; agents never see it.
  if (process.env.SIGNET_LLM_API_KEY) headers.authorization = `Bearer ${process.env.SIGNET_LLM_API_KEY}`;
  let r: HttpResponse;
  try {
    r = await request(`${BASE_URL}/chat/completions`, { method: 'POST', headers, body: JSON.stringify({ ...body, stream: false }), signal, timeoutMs: TIMEOUT_MS });
  } catch (e) {
    if (signal.aborted) throw e;
    throw new UpstreamUnavailable(`cloud LLM unreachable: ${(e as Error).message}`);
  }
  if (r.status === 429 || r.status >= 500) throw new UpstreamUnavailable(`cloud LLM returned ${r.status}`);
  if (!r.ok) throw new UpstreamRejected(r.status, r.text());
  return r.json<ChatResponse>();
}
