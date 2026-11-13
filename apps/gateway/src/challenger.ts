import { DETECTOR_VERSION_SPECS, GRANITE_SAFE, specHash } from '@signet/core';
import type { Ctx } from './ctx';
import { appendRecord } from './ledgerclient';
import * as state from './state';

// Champion / challenger (DA 6 mechanism 4): a new detector version runs beside the current one on live
// traffic, scoring only. It never changes a decision and never delays one: it runs after the champion's
// verdict, in the background, and each result is written to the ledger with the champion's verdict so
// people can review the disagreements before promotion.
//
// DET-SAFE challenger: IBM Granite Guardian 3 2B on a local model server (Ollama API) at
// SIGNET_SAFETY_MODEL_URL. The pin covers the model digest the server reports for that name.

const base = () => (process.env.SIGNET_SAFETY_MODEL_URL ?? 'http://localhost:11434').replace(/\/+$/, '');
let graniteHash: string | null = null;
let checkedAt = 0;

/** Hash of what the model server actually serves under the Granite name (refreshed every 10 minutes). */
export async function graniteRunningHash(): Promise<string | null> {
  if (Date.now() - checkedAt < 600_000) return graniteHash;
  checkedAt = Date.now();
  try {
    const r = await fetch(`${base()}/api/tags`, { signal: AbortSignal.timeout(3000) });
    const m = ((await r.json()) as { models?: { name: string; digest: string }[] }).models?.find((x) => x.name === GRANITE_SAFE.model);
    const spec = DETECTOR_VERSION_SPECS[`DET-SAFE@${GRANITE_SAFE.version}`] as Record<string, unknown>;
    graniteHash = m ? specHash({ ...spec, digest: m.digest }) : null;
  } catch {
    graniteHash = null;
  }
  return graniteHash;
}

export async function graniteScore(text: string, signal?: AbortSignal): Promise<number> {
  const r = await fetch(`${base()}/v1/chat/completions`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, signal,
    body: JSON.stringify({ model: GRANITE_SAFE.model, temperature: 0, max_tokens: 2, logprobs: true, top_logprobs: 5, messages: [{ role: 'system', content: GRANITE_SAFE.risk }, { role: 'user', content: text.slice(-8000) }] }),
  });
  if (!r.ok) throw new Error(`model server answered ${r.status}`);
  const top = ((await r.json()) as { choices?: { logprobs?: { content?: { top_logprobs?: { token: string; logprob: number }[] }[] } }[] }).choices?.[0]?.logprobs?.content?.[0]?.top_logprobs ?? [];
  const p = (t: string) => top.filter((x) => x.token.trim().toLowerCase() === t).reduce((a, x) => a + Math.exp(x.logprob), 0);
  const yes = p('yes');
  const no = p('no');
  if (yes + no === 0) throw new Error('no Yes/No answer');
  return Math.round((yes / (yes + no)) * 1000) / 1000;
}

/** Score the conversation with the DET-SAFE challenger, if one is configured. Fire and forget. */
export function safetyChallenger(ctx: Ctx, conversation: string, where: 'input' | 'output', champion: { category?: string; status: string }) {
  const ch = state.detectors.get('DET-SAFE')?.challenger;
  if (!ch || ch.version !== GRANITE_SAFE.version || !ctx.claims) return;
  const claims = ctx.claims;
  void (async () => {
    const running = await graniteRunningHash();
    let result: Record<string, unknown>;
    if (running !== ch.sha256) result = { status: 'unavailable', reason: running ? 'running hash does not match the pin' : 'model server unreachable' };
    else {
      try {
        const t0 = performance.now();
        const score = await graniteScore(conversation, AbortSignal.timeout(120_000));
        result = { status: 'shadow', score, unsafe: score >= GRANITE_SAFE.threshold, ms: Math.round(performance.now() - t0) };
      } catch (e) {
        result = { status: 'unavailable', reason: (e as Error).message };
      }
    }
    const championUnsafe = champion.category ? champion.category !== 'allow' : null;
    await appendRecord({ kind: 'transaction', agent_id: claims.agent_id, cert_id: ctx.cert?.cert_id ?? null, data: {
      action_type: 'detector_score', request_id: ctx.requestId, target: `DET-SAFE.${where}`, node_id: state.NODE_ID, policy_decision: 'none',
      detector: { id: 'DET-SAFE.challenger', version: ch.version, sha256: running, ...result },
      champion: { status: champion.status, category: champion.category ?? null },
      disagreement: typeof result.unsafe === 'boolean' && championUnsafe !== null ? result.unsafe !== championUnsafe : null,
    } }).catch(() => {});
  })();
}
