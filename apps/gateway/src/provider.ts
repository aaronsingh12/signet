import { env, request, type HttpResponse } from '@signet/core';
import * as state from './state';

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

const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/.test(BASE_URL);

// Credential injection (BP 5.2 step 11): the key comes from the Secrets Broker (kind llm_provider).
// SIGNET_LLM_API_KEY is a dev fallback only and is reported as such. A local Ollama needs none: it
// signs in to ollama.com itself for :cloud models.
async function credential(): Promise<{ value: string | null; source: 'broker' | 'env' | 'none' }> {
  const ref = state.bundle?.llm_credential;
  if (ref) return { value: await state.secret(ref.secret_id), source: 'broker' };
  if (process.env.SIGNET_LLM_API_KEY) return { value: process.env.SIGNET_LLM_API_KEY, source: 'env' };
  return { value: null, source: 'none' };
}

export function credentialAttached() {
  return Boolean(state.bundle?.llm_credential) || Boolean(process.env.SIGNET_LLM_API_KEY) || isLocal;
}

export async function chatCompletion(body: Record<string, unknown>, signal: AbortSignal): Promise<ChatResponse> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  let cred: Awaited<ReturnType<typeof credential>>;
  try {
    cred = await credential();
  } catch (e) {
    throw new UpstreamUnavailable(`cloud LLM credential unavailable from the Secrets Broker: ${(e as Error).message}`);
  }
  if (cred.value) headers.authorization = `Bearer ${cred.value}`;
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

// Real reachability check of the one cloud LLM, every minute: the provider answers, accepts our
// credential and lists the configured model. Reported in /healthz and to the control plane; nothing
// is shown as healthy until this has succeeded.
export interface LlmStatus { state: 'ok' | 'unreachable' | 'unauthorized' | 'model_missing' | 'not_checked'; checked_at: string | null; detail: string; credential: 'broker' | 'env' | 'none'; base_url: string }
let status: LlmStatus = { state: 'not_checked', checked_at: null, detail: 'not checked yet', credential: 'none', base_url: BASE_URL };
export const llmStatus = () => status;

export async function probe(): Promise<LlmStatus> {
  const models = (state.bundle?.catalogue ?? []).map((c) => c.upstream_model ?? c.model); // the name the gateway sends upstream
  let cred: Awaited<ReturnType<typeof credential>> = { value: null, source: 'none' };
  const at = new Date().toISOString();
  try {
    cred = await credential();
    const r = await request(`${BASE_URL}/models`, { headers: cred.value ? { authorization: `Bearer ${cred.value}` } : {}, timeoutMs: 10_000 });
    if (r.status === 401 || r.status === 403) status = { state: 'unauthorized', checked_at: at, detail: `provider refused the credential (${r.status})`, credential: cred.source, base_url: BASE_URL };
    else if (!r.ok) status = { state: 'unreachable', checked_at: at, detail: `provider answered ${r.status}`, credential: cred.source, base_url: BASE_URL };
    else {
      const ids = (r.json<{ data?: { id: string }[] }>().data ?? []).map((m) => m.id);
      const missing = models.filter((m) => !ids.includes(m));
      status = missing.length
        ? { state: 'model_missing', checked_at: at, detail: `provider is reachable but does not list ${missing.join(', ')}`, credential: cred.source, base_url: BASE_URL }
        : { state: 'ok', checked_at: at, detail: `provider lists ${models.join(', ')}`, credential: cred.source, base_url: BASE_URL };
    }
  } catch (e) {
    status = { state: 'unreachable', checked_at: at, detail: (e as Error).message, credential: cred.source, base_url: BASE_URL };
  }
  return status;
}
