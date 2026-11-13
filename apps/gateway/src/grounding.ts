import { sha256, type Tier } from '@signet/core';
import * as state from './state';

// DET-GROUND sampling (DA 3 Tier 2, DA 5: "groundedness on a 1% sample of sessions, higher for T1").
// The choice is a hash of the request ID, so it is reproducible. Only answers that had sources (tool
// results or system context) can be judged. Text sent is what the model saw: tokenised by DLP.
const RATE: Record<Tier, number> = { T1: 0.05, T2: 0.02, T3: 0.01, T4: 0.01 };

export function sampleRate(tier: Tier): number {
  const o = Number(process.env.SIGNET_GROUND_SAMPLE_RATE);
  return Number.isFinite(o) && o >= 0 && o <= 1 && process.env.SIGNET_GROUND_SAMPLE_RATE !== '' && process.env.SIGNET_GROUND_SAMPLE_RATE !== undefined ? o : RATE[tier];
}

export const sampled = (requestId: string, rate: number) => parseInt(sha256(requestId).slice(0, 8), 16) / 0xffffffff < rate;

type Msg = { role?: string; content?: unknown };
const text = (c: unknown): string => (typeof c === 'string' ? c : Array.isArray(c) ? c.map((p) => (typeof p === 'string' ? p : (p as { text?: string })?.text ?? '')).join('') : '');

export function groundingInput(messages: Msg[], answer: string): { question: string; sources: string[]; answer: string } | null {
  const sources = messages.filter((m) => m.role === 'tool' || m.role === 'function' || m.role === 'system').map((m) => text(m.content)).filter((s) => s.trim().length >= 20);
  const question = text([...messages].reverse().find((m) => m.role === 'user')?.content);
  if (!sources.length || !answer.trim()) return null;
  return { question, sources, answer };
}

export function maybeSample(agentId: string, requestId: string, tier: Tier, messages: Msg[], answer: string): boolean {
  const mode = state.detectors.get('DET-GROUND')?.mode;
  if (mode !== 'shadow' && mode !== 'active') return false;
  if (!sampled(requestId, sampleRate(tier))) return false;
  const input = groundingInput(messages, answer);
  if (!input) return false;
  state.internal('/internal/ground/sample', { method: 'POST', body: JSON.stringify({ agent_id: agentId, request_id: requestId, tier, ...input }) })
    .catch((e: Error) => console.error(`[gateway] groundedness sample not sent: ${e.message}`));
  return true;
}
