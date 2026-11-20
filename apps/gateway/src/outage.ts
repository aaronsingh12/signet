import { GUARDRAIL_PARAMS } from '@signet/core';
import * as state from './state';

// Cloud LLM outage declaration (RB-PROV-04, E42). An outage is declared when, in the current
// 5-minute bucket, upstream errors exceed 20% of requests for at least 30% of active agents (minimum 3
// agents). While declared, upstream errors never count against an agent (RB-PROV-05). Each gateway node
// decides for its own traffic and reports start and end to the ledger.

const OUTAGE = GUARDRAIL_PARAMS.outage;
const BUCKET_MS = OUTAGE.bucket_minutes * 60_000;
let bucketStart = Date.now();
const perAgent = new Map<string, { ok: number; err: number }>();
export const eraseAgentOutage = (agentId: string): void => { perAgent.delete(agentId); };
let declared = false;

function roll() {
  if (Date.now() - bucketStart < BUCKET_MS) return;
  if (declared) report('ended');
  declared = false;
  bucketStart = Date.now();
  perAgent.clear();
}

function report(s: 'declared' | 'ended') {
  const stats = { agents: perAgent.size, failing: [...perAgent.values()].filter((v) => v.err / (v.ok + v.err) > OUTAGE.agent_error_share).length };
  state.internal('/internal/outage', { method: 'POST', body: JSON.stringify({ node_id: state.NODE_ID, state: s, stats }) }).catch(() => {});
  console.log(`[gateway] cloud LLM outage ${s} (${stats.failing}/${stats.agents} agents failing)`);
}

export function record(agentId: string, ok: boolean) {
  roll();
  const v = perAgent.get(agentId) ?? { ok: 0, err: 0 };
  if (ok) v.ok++;
  else v.err++;
  perAgent.set(agentId, v);
  if (!declared && !ok) {
    const failing = [...perAgent.values()].filter((x) => x.err / (x.ok + x.err) > OUTAGE.agent_error_share).length;
    if (failing >= OUTAGE.min_failing_agents && failing / perAgent.size >= OUTAGE.failing_agent_share) {
      declared = true;
      report('declared');
    }
  }
}

export const isDeclared = () => (roll(), declared);
