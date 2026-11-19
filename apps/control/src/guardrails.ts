import {
  ANOM_THRESHOLDS, GUARDRAILS, GUARDRAIL_GROUPS, GUARDRAIL_PARAMS, INJ_THRESHOLDS, PACKS, PIPELINE_STEPS, RULEBOOK,
  RULEBOOK_AREAS, RULEBOOK_DECISIONS, RULEBOOK_RULES, enabledPacks, type Guardrail,
} from '@signet/core';
import { db } from './db';
import * as detectors from './detectors';
import { GATEWAY_STALE_MS } from './counters';
import { reloadSettings } from './tenant';

// The Guardrails page (/guardrails in the console): the catalogue from @signet/core with the values in force
// now. Detector modes come from the registry, caps and hold time from tenant settings, and DLP packs,
// policy engine and environment from what each live gateway node reports in its heartbeat (in production
// gateways run with their own configuration, so the control plane's own environment is only a fallback).

export type GuardrailStatus = 'enforced' | 'shadow' | 'off' | 'findings_only';

interface DetectorRow { id: string; version: string; mode: 'off' | 'shadow' | 'active' }
interface NodeConfig { node: string; dlp_packs: string[] | null; policy_engine: string | null; environment: string | null }

const fmt = (n: number) => n.toLocaleString('en-US');
const band = (t: readonly [number, number]) => `elevated ${t[0]}, high ${t[1]}`;
const TIERS = ['T1', 'T2', 'T3', 'T4'] as const;

function statusOf(g: Guardrail, modes: Map<string, DetectorRow>): GuardrailStatus {
  if (!g.detector) return 'enforced';
  const d = modes.get(g.detector);
  if (!d || d.mode === 'off' || d.version === 'not-deployed') return 'off';
  if (g.detector === 'DET-GROUND') return 'findings_only';
  return d.mode === 'active' ? 'enforced' : 'shadow';
}

/** Guardrail settings reported by gateway nodes seen recently. Nodes on an older build report nothing. */
async function gatewayConfigs(): Promise<NodeConfig[]> {
  const since = new Date(Date.now() - GATEWAY_STALE_MS).toISOString();
  const rows = (await db.prepare('SELECT id, detectors FROM gateway_node WHERE last_seen >= ? ORDER BY id').all(since)) as { id: string; detectors: string | null }[];
  return rows.map((r) => {
    let g: Partial<Omit<NodeConfig, 'node'>> = {};
    try {
      const parsed = r.detectors ? (JSON.parse(r.detectors) as { guardrails?: unknown }).guardrails : null;
      if (parsed && typeof parsed === 'object') g = parsed as typeof g;
    } catch { /* an unreadable report counts as no report */ }
    return {
      node: r.id,
      dlp_packs: Array.isArray(g.dlp_packs) ? g.dlp_packs.map(String) : null,
      policy_engine: typeof g.policy_engine === 'string' ? g.policy_engine : null,
      environment: typeof g.environment === 'string' ? g.environment : null,
    };
  });
}

/** One line for a setting the nodes report: the common value, or each node's value when they differ. */
function fromNodes(nodes: NodeConfig[], pick: (n: NodeConfig) => string | null, fallback: () => string): { text: string; source: 'gateways' | 'control_plane'; consistent: boolean } {
  const reported = nodes.map((n) => ({ node: n.node, value: pick(n) })).filter((x): x is { node: string; value: string } => x.value !== null);
  if (!reported.length) return { text: `${fallback()} (control plane setting; no gateway has reported yet)`, source: 'control_plane', consistent: true };
  const values = [...new Set(reported.map((x) => x.value))];
  const missing = nodes.length - reported.length;
  const tail = missing ? `; ${missing} node(s) on an older build did not report` : '';
  if (values.length === 1) return { text: `${values[0]} (all ${reported.length} gateway node(s)${tail})`, source: 'gateways', consistent: true };
  return { text: `Gateway nodes differ: ${reported.map((x) => `${x.node}: ${x.value}`).join('; ')}${tail}`, source: 'gateways', consistent: false };
}

export async function guardrails() {
  const settings = await reloadSettings();
  const rows = (await detectors.list()) as unknown as DetectorRow[];
  const modes = new Map(rows.map((r) => [r.id, r]));
  const nodes = await gatewayConfigs();
  const { max_input_tokens, max_cost_per_request_usd } = settings.baseline;
  const models = settings.catalogue.map((c) => c.model);
  const P = GUARDRAIL_PARAMS;

  const packList = (packs: string[] | null) => (packs === null ? null : packs.length ? packs.join(', ') : 'none');
  const packs = fromNodes(nodes, (n) => packList(n.dlp_packs), () => {
    try { return packList(enabledPacks())!; } catch (e) { return `configuration error (${(e as Error).message})`; }
  });
  const engine = fromNodes(nodes, (n) => n.policy_engine, () => 'unknown');
  const environment = fromNodes(nodes, (n) => n.environment, () => process.env.SIGNET_ENV ?? 'dev');

  // Live values shown beside a guardrail, by guardrail key.
  const live: Record<string, string> = {
    'input-cap': `${fmt(max_input_tokens)} input tokens per request`,
    'cost-cap': `USD ${fmt(max_cost_per_request_usd)} per request`,
    'one-llm': models.length ? `Catalogue: ${models.join(', ')}` : 'No model in the catalogue',
    'hitl-wait': `Hold time ${settings.hitl_wait_seconds} s`,
    'dlp-patterns': `Country packs on: ${packs.text}. Available: ${Object.keys(PACKS).join(', ')}`,
    environment: `Gateway environment: ${environment.text}`,
    precedence: `Policy engine: ${engine.text}`,
    'step-up': `Lasts ${TIERS.map((t) => `${t} ${P.ladder.step_up_minutes[t]} min`).join(', ')}`,
    ladder: `Step-up ${TIERS.map((t) => `${t} ${P.ladder.step_up_minutes[t]} min`).join(', ')}. Throttle ${TIERS.map((t) => `${t} to ${P.ladder.throttle[t].factor * 100}% for ${P.ladder.throttle[t].minutes} min`).join(', ')}`,
    'det-inj': `Prompt thresholds: ${TIERS.map((t) => `${t} ${band(INJ_THRESHOLDS.prompt[t])}`).join('; ')}. Tool results: ${TIERS.map((t) => `${t} ${band(INJ_THRESHOLDS.tool[t])}`).join('; ')}`,
    'det-jb': `Thresholds: ${TIERS.map((t) => `${t} ${band(INJ_THRESHOLDS.prompt[t])}`).join('; ')}`,
    'det-anom': `Thresholds: ${TIERS.map((t) => `${t} ${band(ANOM_THRESHOLDS[t])}`).join('; ')}`,
    'provider-terms': settings.catalogue.map((c) => `${c.model}: region ${c.region}`).join('; '),
  };
  for (const g of GUARDRAILS) {
    const d = g.detector && g.group === 'detectors' ? modes.get(g.detector) : undefined;
    if (d) live[g.key] = `Version ${d.version}, mode ${d.mode}${live[g.key] ? `. ${live[g.key]}` : ''}`;
  }

  const items = GUARDRAILS.map((g) => ({ ...g, status: statusOf(g, modes), live: live[g.key] ?? null }));
  const rules = RULEBOOK_RULES.map((r) => ({
    ...r,
    guardrails: GUARDRAILS.filter((g) => g.rule_ids.includes(r.id) || g.rulebook?.includes(r.id)).map((g) => g.key),
  }));
  const coverage = (c: string) => rules.filter((r) => r.coverage === c).length;
  return {
    rulebook: {
      ...RULEBOOK,
      areas: RULEBOOK_AREAS,
      rules,
      decisions: RULEBOOK_DECISIONS,
      counts: { total: rules.length, enforced: coverage('enforced'), partial: coverage('partial'), not_built: coverage('not_built'), guidance: coverage('guidance') },
    },
    groups: GUARDRAIL_GROUPS,
    pipeline: PIPELINE_STEPS,
    items,
    counts: {
      total: items.length,
      enforced: items.filter((i) => i.status === 'enforced').length,
      shadow: items.filter((i) => i.status === 'shadow').length,
      off: items.filter((i) => i.status === 'off').length,
    },
    gateways: {
      reporting: nodes.filter((n) => n.dlp_packs !== null || n.policy_engine !== null).length,
      live: nodes.length,
      consistent: packs.consistent && engine.consistent && environment.consistent,
    },
    sources: [
      { id: 'BP', title: 'Signet Product & Engineering Blueprint' },
      { id: 'DA', title: 'Signet Decision Architecture and Self-Governance' },
      { id: 'RB', title: 'Signet Rulebook v0.1 (2026-10-28); v0.2 additions are cited by the code only' },
    ],
  };
}
