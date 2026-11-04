import { db } from './db';
import { keylessKpi } from './discovery';
import { GATEWAY_LIVE_MS, GATEWAY_STALE_MS } from './counters';
import { tenant } from './tenant';

// Command Center figures (BP 14.1), computed from the registry and the ledger.
export async function commandCenter() {
  const since24 = new Date(Date.now() - 86_400_000).toISOString();
  const since60 = new Date(Date.now() - 3_600_000).toISOString();
  const tiers = (await db.prepare("SELECT tier, status, COUNT(*) AS n FROM agent WHERE tenant_id = ? AND status != 'retired' GROUP BY tier, status").all(tenant.id)) as { tier: string; status: string; n: number }[];
  const tx24 = (await db.prepare("SELECT COUNT(*) AS n, SUM(CASE WHEN (jsonb_extract_path_text(data::jsonb, 'ladder_level'))::double precision >= 1 THEN 1 ELSE 0 END) AS blocked FROM ledger_record WHERE kind = 'transaction' AND ts >= ?").get(since24)) as { n: number; blocked: number | null };
  const decisions = (await db.prepare("SELECT jsonb_extract_path_text(data::jsonb, 'policy_decision') AS d, COUNT(*) AS n FROM ledger_record WHERE kind = 'transaction' AND ts >= ? GROUP BY d").all(since60)) as { d: string; n: number }[];
  const kills = (await db.prepare("SELECT e.id, e.published_ms, MAX(k.latency_ms) AS max_ms, COUNT(k.gateway_node_id) AS acks, e.nodes_expected FROM enforcement_event e LEFT JOIN kill_ack k ON k.event_id = e.id WHERE e.level = 'killed' AND e.published_at >= ? GROUP BY e.id").all(since24)) as { max_ms: number | null }[];
  const expiring = (await db.prepare("SELECT a.handle, a.tier, c.valid_to FROM certificate c JOIN agent a ON a.id = c.agent_id WHERE c.status = 'active' AND c.valid_to <= ? ORDER BY c.valid_to LIMIT 10").all(new Date(Date.now() + 30 * 86_400_000).toISOString()));
  const latency = (await db.prepare("SELECT (jsonb_extract_path_text(data::jsonb, 'latency_ms_gateway'))::double precision AS ms FROM ledger_record WHERE kind = 'transaction' AND ts >= ? AND (jsonb_extract_path_text(data::jsonb, 'latency_ms_gateway'))::double precision IS NOT NULL ORDER BY ms").all(since24)) as { ms: number }[];
  const p95 = latency.length ? latency[Math.min(latency.length - 1, Math.floor(latency.length * 0.95))]!.ms : null;
  const nodes = (await db.prepare('SELECT id, last_seen, bundle_version, llm_status FROM gateway_node WHERE last_seen >= ? ORDER BY id').all(new Date(Date.now() - GATEWAY_STALE_MS).toISOString())) as { id: string; last_seen: string; llm_status: string | null }[];
  return {
    tenant: { id: tenant.id, name: tenant.name },
    agents_by_tier_status: tiers,
    transactions_24h: tx24.n,
    blocks_24h: tx24.blocked ?? 0,
    decisions_60m: decisions,
    kills_24h: kills.length,
    max_kill_propagation_ms: kills.reduce((m, k) => Math.max(m, k.max_ms ?? 0), 0) || null,
    gateway_p95_ms_24h: p95,
    expiring_30d: expiring,
    keyless: (await keylessKpi()),
    gateways: nodes.map((n) => ({ ...n, llm_status: n.llm_status ? JSON.parse(n.llm_status) : null, healthy: Date.now() - Date.parse(n.last_seen) < GATEWAY_LIVE_MS })),
    // The cloud LLM as the gateways last saw it; "unknown" until a live node has checked.
    cloud_llm: llmStatus(nodes),
  };
}

type LlmStatus = { state: 'ok' | 'unreachable' | 'unauthorized' | 'model_missing' | 'not_checked'; checked_at: string | null; detail: string; credential: 'broker' | 'env' | 'none'; base_url: string };
function llmStatus(nodes: { last_seen: string; llm_status: string | null }[]): (LlmStatus & { verified: boolean }) | { state: 'unknown'; verified: false; detail: string } {
  const live = nodes.filter((n) => Date.now() - Date.parse(n.last_seen) < 30_000 && n.llm_status).map((n) => JSON.parse(n.llm_status!) as LlmStatus);
  if (!live.length) return { state: 'unknown', verified: false, detail: 'no live gateway node has reported a check of the cloud LLM' };
  const latest = live.sort((a, b) => String(b.checked_at).localeCompare(String(a.checked_at)))[0]!;
  return { ...latest, verified: latest.state === 'ok' };
}
