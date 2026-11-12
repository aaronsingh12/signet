import {
  RESTRICTED_TAGS, canonicalize, evaluateTs, newId, promptDecision, scan, sha256,
  type CompiledPolicy, type DataTag, type Rollout, type Tier, DATA_TAGS } from '@signet/core';
import * as approvals from './approvals';
import { compilePolicy } from './compile';
import { db, nowIso, tx } from './db';
import * as enforcement from './enforcement';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import * as hub from './hub';
import * as ledger from './ledger';
import { notify } from './notify';
import { correlation, enqueue } from './outbox';
import { can, singleOperator, type Principal, type Role } from './rbac';
import { activeCertificate, getAgent, signSeal, teamOf, validateSeal, type AgentRow, type SealInput } from './registry';
import { markRotationDue } from './secrets';
import { getTemplate, manifestFrom } from './templates';
import { tenant } from './tenant';
import { GATEWAY_AUTH_ERRORS } from './gateway-auth';

// The 8-stage onboarding lifecycle (BP 6): Propose, Classify, Assess, Test, Approve, Deploy, Monitor,
// Retire. Every stage transition is written to the lifecycle ledger, and each stage has an exit gate.
// The risk tier set at Classify decides how heavy every later stage is.

export const STAGES = ['propose', 'classify', 'assess', 'test', 'approve', 'deploy', 'monitor', 'retire'] as const;
export type Stage = (typeof STAGES)[number];

const DAY = 86_400_000;
const isDev = () => (process.env.SIGNET_ENV ?? 'dev') === 'dev';

export interface Intake {
  business_value?: string;
  users_affected: ('internal' | 'customers' | 'public')[];
  decisions_about_individuals: boolean;
  individual_domains?: string[]; // credit, employment, insurance, healthcare, education, essential_services
  data_touched: DataTag[];
  build_type?: 'in_house' | 'vendor' | 'saas';
  planned_tools?: string[];
  reversibility?: 'yes' | 'partly' | 'no';
  expected_daily_cost_usd?: number;
  template?: string | null;
  prohibited_practice?: boolean; // EU AI Act Art. 5 (social scoring, manipulation, ...)
}

interface DeployPlan {
  mode: Rollout['mode'];
  canary: boolean;
  canary_pct: number;
  shadow_days: number;
  mode_since: string;
  overrides: string[];
}

interface LcData {
  intake: Intake;
  manifest: SealInput | null;
  deploy?: DeployPlan;
  cert_id?: string;
  approval_id?: string;
  test_run_id?: string;
}

interface LcRow {
  id: string;
  agent_id: string;
  kind: 'initial' | 'minor' | 'major';
  stage: Stage;
  status: 'in_progress' | 'complete' | 'rejected' | 'retired';
  data: string;
  started_at: string;
  stage_entered_at: string;
  updated_at: string;
}

export type Lifecycle = Omit<LcRow, 'data'> & { data: LcData };
const parse = (r: LcRow): Lifecycle => ({ ...r, data: JSON.parse(r.data) as LcData });

export async function get(id: string): Promise<Lifecycle> {
  const r = (await db.prepare('SELECT * FROM lifecycle WHERE id = ?').get(id)) as LcRow | undefined;
  if (!r) throw notFound(`lifecycle ${id}`);
  return parse(r);
}

export async function forAgent(agentId: string): Promise<Lifecycle[]> {
  return ((await db.prepare('SELECT * FROM lifecycle WHERE agent_id = ? ORDER BY started_at DESC').all(agentId)) as unknown as LcRow[]).map(parse);
}

const saveData = async (id: string, data: LcData) => (await db.prepare('UPDATE lifecycle SET data = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(data), nowIso(), id));

async function move(lc: Lifecycle, to: Stage | null, outcome: 'passed' | 'returned' | 'rejected' | 'skipped', actor: string, gate: Record<string, unknown>, status?: Lifecycle['status']) {
  const now = nowIso();
  (await db.prepare('INSERT INTO stage_record (id, lifecycle_id, stage, outcome, actor, gate, entered_at, exited_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
    newId('evt').replace('evt_', 'stg_'), lc.id, lc.stage, outcome, actor, JSON.stringify(gate), lc.stage_entered_at, now,
  ));
  (await db.prepare('UPDATE lifecycle SET stage = ?, status = ?, stage_entered_at = ?, updated_at = ? WHERE id = ?').run(to ?? lc.stage, status ?? lc.status, now, now, lc.id));
  (await ledger.append({ kind: 'lifecycle', agent_id: lc.agent_id, data: { event: `stage.${lc.stage}.${outcome}`, lifecycle_id: lc.id, from: lc.stage, to: to ?? lc.stage, actor, gate } }));
  if (to && to !== lc.stage) (await notify((await getAgent(lc.agent_id)).owner, 'lifecycle', `${(await getAgent(lc.agent_id)).handle}: ${lc.stage} ${outcome}, now in ${to}`, `/agents/${lc.agent_id}?tab=lifecycle`));
}

async function current(agentId: string): Promise<Lifecycle> {
  const lcs = (await forAgent(agentId)).filter((l) => l.status === 'in_progress');
  if (!lcs.length) throw new PolicyError('BP-6', 'this agent has no lifecycle in progress', 409);
  return lcs[0]!;
}

function assertStage(lc: Lifecycle, stage: Stage) {
  if (lc.status !== 'in_progress') throw new PolicyError('BP-6', `lifecycle is ${lc.status}`, 409);
  if (lc.stage !== stage) throw new PolicyError('BP-6', `the agent is in ${lc.stage}, not ${stage}`, 409);
}

const isTeam = async (agent: AgentRow, p: Principal) => agent.owner === p.id || agent.created_by === p.id || (await teamOf(agent.id)).some((t) => t.user === p.id);
async function assertOwnerSide(agent: AgentRow, p: Principal) {
  if ((await isTeam(agent, p)) || can(p, 'certificates.approve') || p.roles.includes('platform_admin')) return;
  throw forbidden('RBAC', 'only the owner, build team, Risk or Security can work on this stage');
}

// --- Stage 1: Propose ---------------------------------------------------------------------------

// What classification scores must be real values: an unknown audience or data class would score as low risk.
function checkIntake(i: Partial<Intake>) {
  if (i.users_affected !== undefined && (!Array.isArray(i.users_affected) || i.users_affected.some((u) => !['internal', 'customers', 'public'].includes(u)))) throw invalid('users_affected must be a list of internal, customers or public');
  if (i.data_touched !== undefined && (!Array.isArray(i.data_touched) || i.data_touched.some((t) => !DATA_TAGS.includes(t)))) throw invalid('data_touched contains an unknown data class');
  if (i.reversibility !== undefined && !['yes', 'partly', 'no'].includes(i.reversibility)) throw invalid('reversibility must be yes, partly or no');
}

export async function start(agent: AgentRow, intakeIn: Partial<Intake>, p: Principal, kind: Lifecycle['kind'] = 'initial', manifest?: SealInput | null): Promise<Lifecycle> {
  checkIntake(intakeIn);
  const tpl = getTemplate(intakeIn.template ?? undefined);
  const intake: Intake = {
    users_affected: intakeIn.users_affected ?? tpl?.users_affected ?? [],
    decisions_about_individuals: intakeIn.decisions_about_individuals ?? tpl?.decisions_about_individuals ?? false,
    individual_domains: intakeIn.individual_domains ?? [],
    data_touched: intakeIn.data_touched ?? tpl?.data_touched ?? [],
    build_type: intakeIn.build_type ?? 'in_house',
    planned_tools: intakeIn.planned_tools ?? tpl?.suggested_actions.map((a) => `${a.name} (${a.impact})`) ?? [],
    reversibility: intakeIn.reversibility ?? 'partly',
    business_value: intakeIn.business_value ?? '',
    expected_daily_cost_usd: intakeIn.expected_daily_cost_usd,
    template: tpl?.id ?? null,
    prohibited_practice: intakeIn.prohibited_practice ?? false,
  };
  const id = newId('evt').replace('evt_', 'lcy_');
  const now = nowIso();
  const draft = manifest ?? manifestFrom(tpl);
  // A vendor-hosted agent's model is outside Signet: its manifest lists only the company tools it calls.
  const data: LcData = { intake, manifest: draft && agent.kind === 'third_party' ? { ...draft, models: [] } : draft };
  (await db.prepare('INSERT INTO lifecycle (id, agent_id, kind, stage, status, data, started_at, stage_entered_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, agent.id, kind, 'propose', 'in_progress', JSON.stringify(data), now, now, now));
  (await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'lifecycle.started', lifecycle_id: id, kind, template: intake.template, actor: p.id } }));
  return (await get(id));
}

export async function updateIntake(lcId: string, patch: Partial<Intake>, p: Principal) {
  const lc = (await get(lcId));
  assertStage(lc, 'propose');
  (await assertOwnerSide((await getAgent(lc.agent_id)), p));
  checkIntake(patch);
  (await saveData(lc.id, { ...lc.data, intake: { ...lc.data.intake, ...patch } }));
  return (await view(lc.id));
}

async function proposeGate(lc: Lifecycle) {
  const a = (await getAgent(lc.agent_id));
  const i = lc.data.intake;
  return {
    owner_and_sponsor: !!a.owner && !!a.sponsor,
    purpose: a.purpose.trim().length >= 10,
    autonomy_set: !!a.autonomy_level,
    users_affected: i.users_affected.length > 0,
    data_declared: Array.isArray(i.data_touched),
  };
}

export async function submitPropose(lcId: string, p: Principal) {
  const lc = (await get(lcId));
  assertStage(lc, 'propose');
  (await assertOwnerSide((await getAgent(lc.agent_id)), p));
  const gate = (await proposeGate(lc));
  const failed = Object.entries(gate).filter(([, v]) => !v).map(([k]) => k);
  if (failed.length) throw new PolicyError('BP-6-S1', `exit gate not met: ${failed.join(', ')}`, 422, { gate });
  (await tx(async () => {
    (await writeClassification(lc, {}, null));
    (await move(lc, 'classify', 'passed', p.id, gate));
  }));
  return (await view(lc.id));
}

// --- Stage 2: Classify --------------------------------------------------------------------------

const FACTORS = ['autonomy', 'data_sensitivity', 'decision_impact', 'external_exposure', 'reversibility'] as const;
type Factor = (typeof FACTORS)[number];
const WEIGHTS: Record<Factor, number> = { autonomy: 0.25, data_sensitivity: 0.25, decision_impact: 0.25, external_exposure: 0.15, reversibility: 0.1 };
const ANNEX_III = ['credit', 'employment', 'insurance', 'healthcare', 'education', 'essential_services'];

export function suggestFactors(agent: AgentRow, i: Intake): Record<Factor, number> {
  const tools = (i.planned_tools ?? []).join(' ').toLowerCase();
  const data = i.data_touched;
  return {
    autonomy: { L0: 1, L1: 2, L2: 3, L3: 4, L4: 5 }[agent.autonomy_level],
    data_sensitivity: data.some((t) => RESTRICTED_TAGS.includes(t)) ? 5 : data.some((t) => t === 'personal' || t === 'financial_account') ? 4 : data.some((t) => t === 'confidential_doc' || t === 'source_code') ? 3 : data.length ? 2 : 1,
    decision_impact: i.decisions_about_individuals ? 5 : /critical|payment|refund|payout|delete|grant|deploy/.test(tools) ? 4 : /privileged|email|write|create|update/.test(tools) ? 3 : 2,
    external_exposure: i.users_affected.includes('public') ? 5 : i.users_affected.includes('customers') ? 4 : 2,
    reversibility: i.reversibility === 'no' ? 5 : i.reversibility === 'partly' ? 3 : 1,
  };
}

export function scoreToTier(score: number): Tier {
  return score >= 4 ? 'T1' : score >= 3 ? 'T2' : score >= 2 ? 'T3' : 'T4';
}

async function writeClassification(lc: Lifecycle, overrides: Partial<Record<Factor, { value: number; reason: string; by: string }>>, confirmedBy: string | null) {
  const agent = (await getAgent(lc.agent_id));
  const i = lc.data.intake;
  const factors = suggestFactors(agent, i);
  for (const [k, o] of Object.entries(overrides)) if (o) factors[k as Factor] = o.value;
  const score = Math.round(FACTORS.reduce((s, f) => s + factors[f] * WEIGHTS[f], 0) * 100) / 100;
  let tier = scoreToTier(score);
  const reasons = [`weighted score ${score} → ${tier}`];
  // RB-INV-14: decisions about individuals' credit, employment, insurance, healthcare, education or
  // essential services make an agent at least T2.
  const annex = i.decisions_about_individuals && (i.individual_domains ?? []).some((d) => ANNEX_III.includes(d));
  if ((annex || i.decisions_about_individuals) && (tier === 'T3' || tier === 'T4')) {
    tier = 'T2';
    reasons.push('decisions about individuals: at least T2 (RB-INV-14)');
  }
  const category = i.prohibited_practice ? 'eu_ai_act:prohibited' : annex ? 'eu_ai_act:high_risk' : i.users_affected.some((u) => u !== 'internal') ? 'eu_ai_act:limited_risk' : 'eu_ai_act:minimal_risk';
  const frameworks = ['NIST AI RMF 1.0', 'OWASP LLM Top 10', 'ISO/IEC 42001'];
  if (category !== 'eu_ai_act:minimal_risk') frameworks.push('EU AI Act');
  if (i.data_touched.some((t) => t === 'personal' || t === 'special_category')) frameworks.push('GDPR');
  (await db.prepare(
    `INSERT INTO classification (lifecycle_id, factors, score, tier, regulatory_category, frameworks, reasons, overrides, confirmed_by, confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(lifecycle_id) DO UPDATE SET factors = excluded.factors, score = excluded.score, tier = excluded.tier, regulatory_category = excluded.regulatory_category,
       frameworks = excluded.frameworks, reasons = excluded.reasons, overrides = excluded.overrides, confirmed_by = excluded.confirmed_by, confirmed_at = excluded.confirmed_at`,
  ).run(lc.id, JSON.stringify(factors), score, tier, category, JSON.stringify(frameworks), JSON.stringify(reasons), JSON.stringify(overrides), confirmedBy, confirmedBy ? nowIso() : null));
  return { factors, score, tier, category, frameworks, reasons };
}

export async function classificationOf(lcId: string) {
  const r = (await db.prepare('SELECT * FROM classification WHERE lifecycle_id = ?').get(lcId)) as Record<string, string | number | null> | undefined;
  if (!r) return null;
  return { ...r, factors: JSON.parse(String(r.factors)), frameworks: JSON.parse(String(r.frameworks)), reasons: JSON.parse(String(r.reasons)), overrides: JSON.parse(String(r.overrides)) } as {
    factors: Record<Factor, number>; score: number; tier: Tier; regulatory_category: string; frameworks: string[]; reasons: string[]; overrides: Record<string, unknown>; confirmed_by: string | null;
  };
}

// Overrides need Risk/Compliance and a reason (BP 6 Stage 2). T1/T2 are confirmed by the risk team;
// T3/T4 by the owner.
export async function classify(lcId: string, p: Principal, input: { overrides?: Partial<Record<Factor, number>>; reason?: string; confirm?: boolean }) {
  const lc = (await get(lcId));
  assertStage(lc, 'classify');
  const agent = (await getAgent(lc.agent_id));
  const existing = (await classificationOf(lc.id))?.overrides ?? {};
  const overrides = { ...(existing as Record<string, { value: number; reason: string; by: string }>) };
  if (input.overrides && Object.keys(input.overrides).length) {
    if (!p.roles.includes('risk_officer') && !p.roles.includes('governance_board')) throw forbidden('BP-6-S2', 'only Risk/Compliance can override classification factors');
    if ((await isTeam(agent, p)) && !singleOperator(p)) throw forbidden('RB-INV-09', `${p.id} proposed, owns or builds this agent and cannot change its classification`);
    if (!input.reason?.trim()) throw invalid('an override needs a reason');
    for (const [k, v] of Object.entries(input.overrides)) {
      if (!FACTORS.includes(k as Factor) || !(Number(v) >= 1 && Number(v) <= 5)) throw invalid(`factor ${k} must be 1-5`);
      overrides[k] = { value: Number(v), reason: input.reason, by: p.id };
    }
  }
  let result = (await writeClassification(lc, overrides as never, null));
  if (!input.confirm) return (await view(lc.id));
  if (result.category === 'eu_ai_act:prohibited') {
    (await tx(async () => {
      (await move(lc, null, 'rejected', p.id, { regulatory_category: result.category, rule: 'RB-INV-13' }, 'rejected'));
      (await db.prepare("UPDATE agent SET status = 'rejected' WHERE id = ?").run(agent.id));
    }));
    throw new PolicyError('RB-INV-13', 'an EU AI Act prohibited use is rejected at Classify', 422);
  }
  const riskTeam = p.roles.includes('risk_officer') || p.roles.includes('governance_board');
  if ((result.tier === 'T1' || result.tier === 'T2') && !riskTeam) throw forbidden('BP-6-S2', `${result.tier} classifications are confirmed by the risk team`);
  if ((result.tier === 'T1' || result.tier === 'T2') && (await isTeam(agent, p)) && !singleOperator(p)) throw forbidden('RB-INV-09', `${p.id} proposed, owns or builds this agent and cannot confirm its ${result.tier} classification`);
  if (!riskTeam && agent.owner !== p.id) throw forbidden('BP-6-S2', 'the owner or the risk team confirms the classification');
  (await tx(async () => {
    result = (await writeClassification(lc, overrides as never, p.id));
    (await db.prepare('UPDATE agent SET tier = ? WHERE id = ?').run(result.tier, agent.id));
    for (const type of requiredAssessments(result.tier)) {
      (await db.prepare('INSERT INTO assessment (id, lifecycle_id, type, status, content, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING').run(
        newId('evt').replace('evt_', 'asm_'), lc.id, type, 'draft', JSON.stringify(type === 'questionnaire' ? questionnaireFor(lc.data.intake, agent) : {}), 'system', nowIso(),
      ));
    }
    (await move(lc, 'assess', 'passed', p.id, { tier: result.tier, score: result.score, regulatory_category: result.category, frameworks: result.frameworks }));
  }));
  if (result.tier !== 'T4') (await enqueue('risk.upsert', correlation('risk', agent.id), { agent_id: agent.id, handle: agent.handle, tier: result.tier, score: result.score, regulatory_category: result.category, owner: agent.owner, statement: `AI agent ${agent.handle}: ${result.reasons.join('; ')}` }));
  return (await view(lc.id));
}

// --- Stage 3: Assess ----------------------------------------------------------------------------

export function requiredAssessments(tier: Tier): string[] {
  // BP 6 path weight: T4 AIBOM + CVE (Phase 3), T3 + questionnaire, T2 + threat model + impact, T1 + DPIA + vendor risk.
  return { T4: [], T3: ['questionnaire'], T2: ['questionnaire', 'threat_model', 'impact'], T1: ['questionnaire', 'threat_model', 'impact', 'dpia', 'vendor_risk'] }[tier];
}

const QUESTIONS = [
  { id: 'q1', control: 'SGC-GOV-001', severity: 'high', text: 'Is a named, active owner accountable for this agent?' },
  { id: 'q2', control: 'SGC-TOOL-004', severity: 'critical', text: 'Is every tool the agent may call listed with its actions and limits?' },
  { id: 'q3', control: 'SGC-IDN-002', severity: 'high', text: 'Will the agent run without holding any model or tool credentials?' },
  { id: 'q4', control: 'SGC-DATA-001', severity: 'high', text: 'Is the personal or sensitive data the agent sees declared and minimised?' },
  { id: 'q5', control: 'SGC-HUMAN-001', severity: 'high', text: 'Is a person able to review or override the agent\'s high-impact actions?' },
  { id: 'q6', control: 'SGC-TRANS-001', severity: 'medium', text: 'Are users told when they are dealing with an AI agent?' },
  { id: 'q7', control: 'SGC-SEC-001', severity: 'high', text: 'Has the prompt and tool-response handling been tested against injection?' },
  { id: 'q8', control: 'SGC-RESP-002', severity: 'medium', text: 'Is there an incident route if the agent is quarantined or killed?' },
  { id: 'q9', control: 'SGC-VALUE-001', severity: 'low', text: 'Is the expected business value recorded?' },
  { id: 'q10', control: 'SGC-FAIR-001', severity: 'high', text: 'If the agent affects individuals, is outcome bias tested?' },
];

function questionnaireFor(i: Intake, a: AgentRow) {
  // Pre-filled from the intake where the answer is already known; the rest is asked.
  const pre: Record<string, string> = { q1: a.owner ? 'yes' : '', q3: 'yes', q9: i.business_value ? 'yes' : '', q10: i.decisions_about_individuals ? '' : 'na' };
  return { questions: QUESTIONS, answers: Object.fromEntries(QUESTIONS.map((q) => [q.id, { answer: pre[q.id] ?? '', note: '' }])) };
}

export async function assessments(lcId: string) {
  return ((await db.prepare('SELECT * FROM assessment WHERE lifecycle_id = ? ORDER BY type').all(lcId)) as { content: string }[]).map((a) => ({ ...a, content: JSON.parse(a.content) }));
}

export async function saveAssessment(lcId: string, type: string, content: Record<string, unknown>, complete: boolean, p: Principal) {
  const lc = (await get(lcId));
  assertStage(lc, 'assess');
  const agent = (await getAgent(lc.agent_id));
  if (!(await isTeam(agent, p)) && !p.roles.includes('risk_officer') && !p.roles.includes('security_officer')) throw forbidden('RBAC', 'only the build team, Risk or Security edit assessments');
  const row = (await db.prepare('SELECT id FROM assessment WHERE lifecycle_id = ? AND type = ?').get(lc.id, type)) as { id: string } | undefined;
  if (!row) throw notFound(`assessment ${type}`);
  if (complete) {
    if (type === 'questionnaire') {
      const answers = (content.answers ?? {}) as Record<string, { answer: string; note?: string }>;
      const missing = QUESTIONS.filter((q) => !['yes', 'partial', 'no', 'na'].includes(answers[q.id]?.answer ?? ''));
      if (missing.length) throw invalid(`answer every question (${missing.map((q) => q.id).join(', ')})`);
      // Each "no" or "partly" becomes a gap against its control (BP 6 Stage 3 gap handling).
      for (const q of QUESTIONS.filter((x) => answers[x.id]!.answer === 'no' || answers[x.id]!.answer === 'partial')) {
        if (!(await db.prepare("SELECT 1 FROM gap WHERE lifecycle_id = ? AND control_id = ? AND status != 'closed'").get(lc.id, q.control))) (await addGap(lc.id, { control_id: q.control, severity: q.severity, title: q.text.replace(/\?$/, ': not yet') }, p));
      }
    } else {
      const empty = Object.values(content).filter((v) => typeof v === 'string' && !v.trim());
      if (!Object.keys(content).length || empty.length) throw invalid(`complete every field of the ${type.replace('_', ' ')}`);
    }
  }
  (await db.prepare('UPDATE assessment SET content = ?, status = ?, updated_by = ?, updated_at = ? WHERE id = ?').run(JSON.stringify(content), complete ? 'complete' : 'draft', p.id, nowIso(), row.id));
  if (complete) (await ledger.append({ kind: 'lifecycle', agent_id: lc.agent_id, data: { event: 'assessment.completed', lifecycle_id: lc.id, type, content_sha256: sha256(canonicalize(content)), actor: p.id } }));
  return (await view(lc.id));
}

export async function setManifest(lcId: string, manifest: SealInput, p: Principal) {
  const lc = (await get(lcId));
  if (lc.stage !== 'assess' && lc.stage !== 'propose') throw new PolicyError('BP-6-S3', 'the manifest is drafted in Propose or Assess; later changes need a new version', 409);
  const agent = (await getAgent(lc.agent_id));
  (await assertOwnerSide(agent, p));
  (await validateSeal(agent, manifest));
  (await saveData(lc.id, { ...lc.data, manifest }));
  (await ledger.append({ kind: 'lifecycle', agent_id: lc.agent_id, data: { event: 'manifest.drafted', lifecycle_id: lc.id, manifest_sha256: sha256(canonicalize(manifest)), actor: p.id } }));
  return (await view(lc.id));
}

export const gapsOf = async (lcId: string) => (await db.prepare('SELECT * FROM gap WHERE lifecycle_id = ? ORDER BY CASE severity WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 ELSE 3 END, created_at').all(lcId));

export async function addGap(lcId: string, input: { control_id?: string; severity: string; title: string; mitigation?: string }, p: Principal) {
  const lc = (await get(lcId));
  if (!['critical', 'high', 'medium', 'low'].includes(input.severity)) throw invalid('severity must be critical, high, medium or low');
  if (!input.title?.trim()) throw invalid('a gap needs a title');
  const id = newId('evt').replace('evt_', 'gap_');
  (await db.prepare('INSERT INTO gap (id, lifecycle_id, agent_id, control_id, severity, title, mitigation, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
    id, lc.id, lc.agent_id, input.control_id ?? null, input.severity, input.title.trim(), input.mitigation ?? null, 'open', p.id, nowIso(), nowIso(),
  ));
  (await ledger.append({ kind: 'lifecycle', agent_id: lc.agent_id, data: { event: 'gap.created', gap_id: id, control_id: input.control_id ?? null, severity: input.severity, actor: p.id } }));
  (await enqueue('issue.upsert', correlation('gap', id), { agent_id: lc.agent_id, handle: (await getAgent(lc.agent_id)).handle, control_id: input.control_id, severity: input.severity, title: input.title, state: 'open' }));
  return id;
}

export async function updateGap(gapId: string, input: { status: 'mitigated' | 'closed' | 'open'; mitigation?: string }, p: Principal) {
  const g = (await db.prepare('SELECT * FROM gap WHERE id = ?').get(gapId)) as { lifecycle_id: string; agent_id: string; status: string; title: string; severity: string } | undefined;
  if (!g) throw notFound(`gap ${gapId}`);
  if (!['mitigated', 'closed', 'open'].includes(input.status)) throw invalid('status must be mitigated, closed or open');
  if (input.status === 'mitigated' && !input.mitigation?.trim()) throw invalid('describe the mitigation');
  (await assertOwnerSide((await getAgent(g.agent_id)), p));
  (await db.prepare('UPDATE gap SET status = ?, mitigation = COALESCE(?, mitigation), updated_at = ? WHERE id = ?').run(input.status, input.mitigation ?? null, nowIso(), gapId));
  (await ledger.append({ kind: 'lifecycle', agent_id: g.agent_id, data: { event: `gap.${input.status}`, gap_id: gapId, mitigation: input.mitigation ?? null, actor: p.id } }));
  (await enqueue('issue.upsert', correlation('gap', gapId), { agent_id: g.agent_id, title: g.title, severity: g.severity, state: input.status }));
  return (await db.prepare('SELECT * FROM gap WHERE id = ?').get(gapId));
}

// Risk acceptance of a High gap goes to the approvals engine (BP 7.2 matrix row "Risk acceptance").
export async function requestAcceptance(gapId: string, p: Principal, input: { reason: string; until: string }) {
  const g = (await db.prepare('SELECT * FROM gap WHERE id = ?').get(gapId)) as { id: string; lifecycle_id: string; agent_id: string; severity: string; title: string; control_id: string | null; status: string } | undefined;
  if (!g) throw notFound(`gap ${gapId}`);
  if (g.severity === 'critical') throw new PolicyError('BP-6-S3', 'critical gaps cannot be risk-accepted; they must be closed', 422);
  if (g.status !== 'open') throw new PolicyError('BP-6-S3', `gap is ${g.status}`, 409);
  if (!input.reason?.trim()) throw invalid('a reason is required');
  const until = Date.parse(input.until);
  if (!(until > Date.now() && until < Date.now() + 366 * DAY)) throw invalid('acceptance needs an expiry date within a year');
  const agent = (await getAgent(g.agent_id));
  const slots: approvals.Slot[] =
    agent.tier === 'T4' ? [{ slot: 'owner', label: 'Owner', roles: [], count: 1, owner_only: true }]
    : agent.tier === 'T3' ? [{ slot: 'owner', label: 'Owner', roles: [], count: 1, owner_only: true }, { slot: 'security', label: 'Security', roles: ['security_officer'], count: 1 }]
    : agent.tier === 'T2' ? [{ slot: 'risk', label: 'Risk/Compliance', roles: ['risk_officer'], count: 1 }]
    : [{ slot: 'cro', label: 'CRO or delegate', roles: ['risk_officer', 'governance_board'], count: 1 }];
  const req = (await approvals.create({
    type: 'risk_acceptance', agent_id: agent.id, subject_ref: gapId, tier: agent.tier, created_by: p.id, sla_ms: 5 * DAY,
    title: `Risk acceptance · ${g.severity} gap · ${agent.handle}`, summary: `${g.control_id ?? 'gap'}: ${g.title}. Accept until ${input.until.slice(0, 10)}. ${input.reason}`,
    pack: { gap: g, agent: { id: agent.id, handle: agent.handle, tier: agent.tier }, reason: input.reason, until: new Date(until).toISOString() }, slots,
  }));
  (await db.prepare('UPDATE gap SET acceptance_request_id = ?, updated_at = ? WHERE id = ?').run(req.id, nowIso(), gapId));
  return req;
}

approvals.onDecision('risk_acceptance', async (req, outcome) => {
  if (outcome !== 'approved') return;
  const until = String((req.pack as { until: string }).until);
  (await db.prepare("UPDATE gap SET status = 'accepted', accepted_until = ?, updated_at = ? WHERE id = ?").run(until, nowIso(), req.subject_ref));
  (await ledger.append({ kind: 'lifecycle', agent_id: req.agent_id, data: { event: 'gap.accepted', gap_id: req.subject_ref, until, approval_id: req.id } }));
});

async function assessGate(lc: Lifecycle) {
  const agent = (await getAgent(lc.agent_id));
  const asm = (await assessments(lc.id)) as unknown as { type: string; status: string }[];
  const gaps = (await gapsOf(lc.id)) as { severity: string; status: string }[];
  let manifestOk = false;
  try {
    if (lc.data.manifest) (await validateSeal(agent, lc.data.manifest)), (manifestOk = true);
  } catch {
    manifestOk = false;
  }
  return {
    assessments_complete: requiredAssessments(agent.tier).every((t) => asm.find((a) => a.type === t)?.status === 'complete'),
    manifest_valid: manifestOk,
    no_open_critical_gaps: !gaps.some((g) => g.severity === 'critical' && g.status === 'open'),
    high_gaps_mitigated_or_accepted: !gaps.some((g) => g.severity === 'high' && g.status === 'open'),
  };
}

export async function submitAssess(lcId: string, p: Principal) {
  const lc = (await get(lcId));
  assertStage(lc, 'assess');
  (await assertOwnerSide((await getAgent(lc.agent_id)), p));
  const gate = (await assessGate(lc));
  const failed = Object.entries(gate).filter(([, v]) => !v).map(([k]) => k);
  if (failed.length) throw new PolicyError('BP-6-S3', `exit gate not met: ${failed.join(', ')}`, 422, { gate });
  (await move(lc, 'test', 'passed', p.id, gate));
  return (await view(lc.id));
}

// --- Stage 4: Test ------------------------------------------------------------------------------
// Phase 2 ships the baseline suites, which run the manifest's compiled policy and the DLP engine
// against probes, plus owner-supplied functional, bias and red-team evidence. The live sandbox Test
// Lab with garak/PyRIT probes through the gateway is Phase 3 (E15).

interface SuiteResult {
  suite: string;
  required: boolean;
  passed: boolean;
  cases: number;
  failures: string[];
  value?: number | string;
  threshold?: string;
}

export function runBaselineSuites(agent: AgentRow, manifest: SealInput, intake: Intake, evidence: { functional_score?: number; bias_ratio?: number; red_team_report_sha256?: string }): SuiteResult[] {
  const draft = { cert_id: 'test', agent_id: agent.id, version: 'test', tenant: tenant.id, owner: agent.owner, approvers: [], tier: agent.tier, autonomy_level: agent.autonomy_level, models: manifest.models, tools: manifest.tools ?? [], data_classes: { prompt: manifest.data_classes?.prompt ?? [], forbidden: manifest.data_classes?.forbidden ?? [] }, hitl: manifest.hitl ?? [], limits: manifest.limits, environments: manifest.environments, tags: manifest.tags ?? [], ai_disclosure: true, valid_from: '', valid_to: '', issued_at: '' };
  const policy: CompiledPolicy = compilePolicy(draft, tenant.settings.baseline);
  const ctx = { tainted: false, step_up: false, tool_calls_in_session: 0, tool_calls_limit: null, dlp_tokenised: 0, max_tokens_capped: false };
  const results: SuiteResult[] = [];
  const tier = agent.tier;

  // 1. Default deny: actions outside the manifest must be denied (SGC-TOOL-004).
  const probes = ['mcp://orders.delete_all', 'http://crm.export_everything', 'mcp://unknown.run_shell', ...Object.keys(policy.actions).map((k) => `${k}_admin`)];
  const f1 = probes.filter((key) => evaluateTs({ kind: 'tool', policy, action: { key, args: {} }, context: ctx }).decision !== 'deny');
  results.push({ suite: 'tool_misuse', required: true, passed: !f1.length, cases: probes.length, failures: f1, threshold: '100% blocked' });

  // 2. Argument constraints: generated violations must be denied.
  const f2: string[] = [];
  let n2 = 0;
  for (const a of Object.values(policy.actions)) {
    for (const [arg, c] of Object.entries(a.constraints)) {
      const bad: unknown[] = [];
      if (typeof c.max === 'number') bad.push(c.max + 1);
      if (typeof c.min === 'number') bad.push(c.min - 1);
      if (c.enum) bad.push('__not_allowed__');
      if (c.pattern) bad.push("x' OR 1=1 --");
      if (typeof c.max_length === 'number') bad.push('x'.repeat(c.max_length + 1));
      for (const v of bad) {
        n2++;
        if (evaluateTs({ kind: 'tool', policy, action: { key: a.key, args: { [arg]: v } }, context: ctx }).decision !== 'deny') f2.push(`${a.key}.${arg}=${String(v).slice(0, 20)}`);
      }
    }
  }
  results.push({ suite: 'argument_constraints', required: true, passed: !f2.length, cases: n2, failures: f2, threshold: '100% denied' });

  // 3. Data leakage: canary secrets and card numbers in prompts must never reach the model.
  const model = tenant.settings.catalogue[0]!;
  const canaries = ['key AKIAIOSFODNN7EXAMPLE', 'card 4111 1111 1111 1111', 'postgres://app:s3cretpass@db.internal:5432/x', 'token sk-proj-AbCdEfGhIjKlMnOpQrStUvWx'];
  const f3 = canaries.filter((text) => scan(text).some((f) => promptDecision(f.tag, policy, model).action !== 'block' && f.tag !== 'payment_card') || !scan(text).length);
  const personal = scan('mail maria.lopez@mail.example').every((f) => promptDecision(f.tag, policy, model).action === 'tokenise');
  if (!personal) f3.push('personal data is not tokenised');
  results.push({ suite: 'data_leakage', required: true, passed: !f3.length, cases: canaries.length + 1, failures: f3, threshold: '0 leaks' });

  // 4. Human-in-the-loop: high-impact actions must be held where the Rulebook requires it.
  const f4: string[] = [];
  let n4 = 0;
  for (const a of Object.values(policy.actions)) {
    const needs = (a.impact === 'critical' && tier !== 'T4') || (a.impact === 'privileged' && (tier === 'T1' || tier === 'T2') && a.value_threshold_usd === null) || a.hitl.some((h) => h.arg === null);
    if (!needs) continue;
    n4++;
    if (evaluateTs({ kind: 'tool', policy, action: { key: a.key, args: {} }, context: ctx }).decision !== 'require_approval') f4.push(a.key);
  }
  results.push({ suite: 'hitl_rules', required: tier !== 'T4', passed: !f4.length, cases: n4, failures: f4, threshold: 'every rule holds' });

  // 5. Functional golden set (owner-supplied): >= 85% for T1/T2 (BP 6 Stage 4).
  const fs = evidence.functional_score;
  results.push({ suite: 'functional', required: tier === 'T1' || tier === 'T2', passed: typeof fs === 'number' && fs >= 85, cases: 1, failures: typeof fs === 'number' && fs >= 85 ? [] : [typeof fs === 'number' ? `score ${fs} < 85` : 'no golden-set score supplied'], value: fs, threshold: '>= 85%' });

  // 6. Bias (when the agent affects individuals): disparity ratio within 0.8-1.25.
  const br = evidence.bias_ratio;
  const biasOk = typeof br === 'number' && br >= 0.8 && br <= 1.25;
  results.push({ suite: 'bias', required: intake.decisions_about_individuals, passed: biasOk, cases: 1, failures: biasOk ? [] : [typeof br === 'number' ? `ratio ${br} outside 0.8-1.25` : 'no bias measurement supplied'], value: br, threshold: '0.8-1.25' });

  // 7. Independent red team (T1).
  const rt = evidence.red_team_report_sha256;
  const rtOk = !!rt && /^[0-9a-f]{64}$/.test(rt);
  results.push({ suite: 'red_team', required: tier === 'T1', passed: rtOk, cases: 1, failures: rtOk ? [] : ['no independent red-team report hash'], value: rt, threshold: 'report attached' });
  return results;
}

export async function runTests(lcId: string, p: Principal, evidence: { functional_score?: number; bias_ratio?: number; red_team_report_sha256?: string }) {
  const lc = (await get(lcId));
  assertStage(lc, 'test');
  const agent = (await getAgent(lc.agent_id));
  (await assertOwnerSide(agent, p));
  const suites = runBaselineSuites(agent, lc.data.manifest!, lc.data.intake, evidence);
  const passed = suites.filter((s) => s.required).every((s) => s.passed);
  const report = { agent_id: agent.id, lifecycle_id: lc.id, tier: agent.tier, manifest_sha256: sha256(canonicalize(lc.data.manifest)), suites, passed, run_at: nowIso(), runner: 'signet-baseline/2' };
  const hash = sha256(canonicalize(report));
  const id = newId('evt').replace('evt_', 'tst_');
  (await tx(async () => {
    (await db.prepare('INSERT INTO test_run (id, lifecycle_id, status, suites, report_sha256, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, lc.id, passed ? 'passed' : 'failed', JSON.stringify(report), hash, p.id, nowIso()));
    (await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'test.completed', lifecycle_id: lc.id, test_run_id: id, passed, report_sha256: hash, suites: suites.map((s) => `${s.suite}:${s.required ? (s.passed ? 'pass' : 'FAIL') : 'n/a'}`), actor: p.id } }));
    (await saveData(lc.id, { ...lc.data, test_run_id: id }));
    if (passed) (await move((await get(lc.id)), 'approve', 'passed', p.id, { test_run_id: id, report_sha256: hash }));
    else {
      // Failures return the agent to Assess with findings linked (BP 6 Stage 4).
      for (const s of suites.filter((x) => x.required && !x.passed)) (await addGap(lc.id, { control_id: 'SGC-SEC-001', severity: 'high', title: `Test suite ${s.suite} failed: ${s.failures.slice(0, 3).join('; ')}` }, p));
      (await move((await get(lc.id)), 'assess', 'returned', p.id, { test_run_id: id, failed: suites.filter((x) => x.required && !x.passed).map((x) => x.suite) }));
    }
  }));
  (await enqueue('control_test.create', correlation('test', id), { agent_id: agent.id, handle: agent.handle, result: passed ? 'pass' : 'fail', report_sha256: hash, suites: suites.map((s) => `${s.suite}:${s.passed}`) }));
  if (passed) (await enterApprove((await get(lc.id)), p));
  return { test_run_id: id, passed, report_sha256: hash, suites, lifecycle: (await view(lc.id)) };
}

// --- Stage 5: Approve ---------------------------------------------------------------------------

function certificateSlots(tier: Tier): approvals.Slot[] {
  // BP 7.2 approval matrix, certificate row.
  const owner: approvals.Slot = { slot: 'owner', label: 'Owner', roles: [], count: 1, owner_only: true };
  const security: approvals.Slot = { slot: 'security', label: 'Security', roles: ['security_officer'], count: 1 };
  const risk: approvals.Slot = { slot: 'risk', label: 'Risk/Compliance', roles: ['risk_officer'], count: 1 };
  const board: approvals.Slot = { slot: 'board', label: 'AI Governance Board (quorum 2)', roles: ['governance_board'], count: 2 };
  return { T4: [], T3: [owner, security], T2: [owner, security, risk], T1: [owner, security, risk, board] }[tier];
}

async function approvalPack(lc: Lifecycle) {
  const agent = (await getAgent(lc.agent_id));
  const cls = (await classificationOf(lc.id));
  const test = lc.data.test_run_id ? ((await db.prepare('SELECT report_sha256, suites FROM test_run WHERE id = ?').get(lc.data.test_run_id)) as { report_sha256: string; suites: string }) : null;
  return {
    agent: { id: agent.id, handle: agent.handle, name: agent.name, purpose: agent.purpose, owner: agent.owner, sponsor: agent.sponsor, tier: agent.tier, autonomy_level: agent.autonomy_level, team: (await teamOf(agent.id)) },
    classification: cls && { score: cls.score, tier: cls.tier, factors: cls.factors, regulatory_category: cls.regulatory_category, frameworks: cls.frameworks, reasons: cls.reasons },
    assessments: ((await assessments(lc.id)) as unknown as { type: string; status: string }[]).map((a) => ({ type: a.type, status: a.status })),
    gaps: (await gapsOf(lc.id)),
    test_report: test && { sha256: test.report_sha256, suites: (JSON.parse(test.suites) as { suites: SuiteResult[] }).suites.map((s) => ({ suite: s.suite, required: s.required, passed: s.passed, value: s.value ?? null })) },
    manifest: lc.data.manifest,
    intake: lc.data.intake,
    deploy_plan: deployPlanFor(agent.tier),
  };
}

async function enterApprove(lc: Lifecycle, p: Principal) {
  const agent = (await getAgent(lc.agent_id));
  const pack = (await approvalPack(lc));
  const slots = certificateSlots(agent.tier);
  if (!slots.length) {
    // T4: automatic on pass (BP 7.2).
    (await issueFromLifecycle(lc, [{ user: 'system:auto (T4 on passing tests, BP 7.2)', at: nowIso() }], sha256(canonicalize(pack)), p.id));
    return;
  }
  const req = (await approvals.create({
    type: 'certificate', agent_id: agent.id, subject_ref: lc.id, tier: agent.tier, created_by: p.id, sla_ms: 5 * DAY,
    title: `Certificate approval · ${agent.tier} · ${agent.handle} ${lc.kind === 'initial' ? 'v1' : `(${lc.kind} change)`}`,
    summary: `${agent.name}: ${agent.purpose}`, pack, slots,
  }));
  (await saveData(lc.id, { ...(await get(lc.id)).data, approval_id: req.id }));
}

approvals.onDecision('certificate', async (req, outcome, p) => {
  const lc = (await get(req.subject_ref));
  if (lc.stage !== 'approve' || lc.status !== 'in_progress') return;
  const actor = p?.id ?? 'system';
  if (outcome === 'approved') {
    const approvers = (req.decisions ?? []).filter((d) => d.decision === 'approve').map((d) => ({ user: d.approver, at: d.ts }));
    const conditions = (req.decisions ?? []).map((d) => d.conditions).filter(Boolean);
    (await issueFromLifecycle(lc, approvers, req.pack_hash, actor, conditions as string[]));
  } else if (outcome === 'sent_back') {
    (await move(lc, 'assess', 'returned', actor, { approval_id: req.id, reason: (req.decisions ?? []).at(-1)?.comment ?? '' }));
  } else {
    (await move(lc, null, 'rejected', actor, { approval_id: req.id, reason: (req.decisions ?? []).at(-1)?.comment ?? '' }, 'rejected'));
    if (!(await activeCertificate(lc.agent_id))) (await db.prepare("UPDATE agent SET status = 'rejected' WHERE id = ?").run(lc.agent_id));
  }
});

async function issueFromLifecycle(lc: Lifecycle, approvers: { user: string; at: string }[], packHash: string, actor: string, conditions: string[] = []) {
  const cls = (await classificationOf(lc.id));
  const test = (await db.prepare('SELECT report_sha256 FROM test_run WHERE id = ?').get(lc.data.test_run_id ?? '')) as { report_sha256: string } | undefined;
  const issued = (await signSeal(lc.agent_id, lc.data.manifest!, {
    approvers,
    evidence_refs: { approval_pack_sha256: packHash, test_report_sha256: test?.report_sha256 ?? '', classification_sha256: sha256(canonicalize(cls)), ...(conditions.length ? { conditions_sha256: sha256(conditions.join('\n')) } : {}) },
    regulatory_category: cls?.regulatory_category ?? 'unclassified',
    minor: lc.kind === 'minor',
    actor,
  }));
  const plan = deployPlanFor(issued.certificate.tier);
  (await saveData(lc.id, { ...(await get(lc.id)).data, cert_id: issued.certificate.cert_id, deploy: plan }));
  (await move((await get(lc.id)), 'deploy', 'passed', actor, { cert_id: issued.certificate.cert_id, approvers: approvers.map((a) => a.user), conditions, rollout: plan.mode }));
  hub.publish('bundle', { reason: 'certificate.issued', cert_id: issued.certificate.cert_id });
  (await enqueue('ci.upsert', correlation('agent', lc.agent_id), (await ciPayload(lc.agent_id, 'Installed'))));
  return issued;
}

// --- Stage 6: Deploy ----------------------------------------------------------------------------

function deployPlanFor(tier: Tier): DeployPlan {
  // BP 6 path weight: T4 shadow 1 day, T3 3 days, T2 7 days + canary, T1 14 days + canary.
  const days = { T1: 14, T2: 7, T3: 3, T4: 1 }[tier];
  return { mode: 'shadow', canary: tier === 'T1' || tier === 'T2', canary_pct: 10, shadow_days: days, mode_since: nowIso(), overrides: [] };
}

export async function rollouts(): Promise<Record<string, Rollout>> {
  const out: Record<string, Rollout> = {};
  for (const r of (await db.prepare("SELECT data FROM lifecycle WHERE stage IN ('deploy', 'monitor') AND status = 'in_progress'").all()) as { data: string }[]) {
    const d = JSON.parse(r.data) as LcData;
    if (d.cert_id && d.deploy) out[d.cert_id] = { mode: d.deploy.mode, canary_pct: d.deploy.canary_pct };
  }
  return out;
}

async function deployStats(certId: string, since: string) {
  const rows = (await db.prepare("SELECT jsonb_extract_path_text(data::jsonb, 'policy_decision') AS d, jsonb_extract_path_text(data::jsonb, 'outcome') AS o, jsonb_extract_path_text(data::jsonb, 'shadow_rule_ids') AS r FROM ledger_record WHERE kind = 'transaction' AND cert_id = ? AND ts >= ?").all(certId, since)) as { d: string; o: string; r: string | null }[];
  const wouldBlock = rows.filter((x) => x.d === 'would_block');
  const critical = wouldBlock.filter((x) => /RB-KILL|RB-INV-16|RB-INV-19/.test(x.r ?? ''));
  return { transactions: rows.length, would_block: wouldBlock.length, critical_would_block: critical.length, upstream_errors: rows.filter((x) => x.o === 'upstream_error').length };
}

export async function advanceDeploy(lcId: string, p: Principal, input: { to: 'canary' | 'enforce'; acknowledge_would_blocks?: boolean; dev_override?: boolean; reason?: string }) {
  const lc = (await get(lcId));
  if (lc.stage !== 'deploy' && lc.stage !== 'monitor') throw new PolicyError('BP-6-S6', `rollout cannot advance from ${lc.stage}`, 409);
  assertStage(lc, lc.stage);
  const agent = (await getAgent(lc.agent_id));
  if (agent.owner !== p.id && !p.roles.includes('security_officer')) throw forbidden('BP-6-S6', 'the owner or Security moves a deployment forward');
  const level = (await enforcement.agentLevel(agent.id));
  if (level === 'killed' || level === 'quarantined') throw new PolicyError('BP-5.4', `the agent is ${level}; a deployment cannot move forward`, 409);
  const plan = lc.data.deploy!;
  const stats = (await deployStats(lc.data.cert_id!, plan.mode_since));
  const ageDays = (Date.now() - Date.parse(plan.mode_since)) / DAY;
  const overrides = [...plan.overrides];
  if (input.to === 'canary' && !plan.canary) throw invalid(`${agent.tier} deployments go from shadow straight to enforce`);
  if (input.to === 'canary' && plan.mode !== 'shadow') throw new PolicyError('BP-6-S6', 'canary follows shadow', 409);
  if (input.to === 'enforce' && plan.canary && plan.mode !== 'canary') throw new PolicyError('BP-6-S6', `${agent.tier} deployments run a canary before full enforcement`, 409);
  const needDays = plan.mode === 'shadow' ? plan.shadow_days : 1;
  if (ageDays < needDays) {
    if (!(input.dev_override && isDev() && input.reason?.trim())) throw new PolicyError('BP-6-S6', `${plan.mode} has run ${ageDays.toFixed(2)} of ${needDays} days`, 422, { stats });
    overrides.push(`${plan.mode} period cut short by ${p.id}: ${input.reason}`);
  }
  if (stats.critical_would_block > 0 && !input.acknowledge_would_blocks) {
    throw new PolicyError('BP-6-S6', `${stats.critical_would_block} critical would-block decision(s) in ${plan.mode} need an explanation before moving on`, 422, { stats });
  }
  if (plan.mode === 'canary' && stats.transactions >= 20 && stats.upstream_errors / stats.transactions > 0.05) throw new PolicyError('BP-6-S6', 'canary error rate is above 5%', 422, { stats });
  const gate = { from: plan.mode, to: input.to, stats, overrides: overrides.slice(plan.overrides.length) };
  (await tx(async () => {
    if (input.to === 'canary') {
      (await saveData(lc.id, { ...lc.data, deploy: { ...plan, mode: 'canary', mode_since: nowIso(), overrides } }));
      (await ledger.append({ kind: 'lifecycle', agent_id: agent.id, cert_id: lc.data.cert_id, data: { event: 'deploy.canary', lifecycle_id: lc.id, canary_pct: plan.canary_pct, gate, actor: p.id } }));
    } else {
      (await saveData(lc.id, { ...lc.data, deploy: { ...plan, mode: 'enforce', mode_since: nowIso(), overrides } }));
      (await move((await get(lc.id)), 'monitor', 'passed', p.id, gate, 'complete'));
    }
  }));
  hub.publish('bundle', { reason: `deploy.${input.to}`, cert_id: lc.data.cert_id });
  (await enqueue('ci.upsert', correlation('agent', agent.id), (await ciPayload(agent.id, 'Operational'))));
  return (await view(lc.id));
}

// --- Stage 7: Monitor ---------------------------------------------------------------------------

/** Start operational monitoring on verified traffic, preserving every shadow/canary promotion gate. */
export async function monitorConnectedAgent(agentId: string): Promise<void> {
  await tx(async () => {
    const row = await db.prepare("SELECT id FROM lifecycle WHERE agent_id = ? AND stage = 'deploy' AND status = 'in_progress' ORDER BY started_at DESC LIMIT 1 FOR UPDATE").get(agentId) as { id: string } | undefined;
    if (!row) return;
    const lc = await get(row.id);
    const active = (await activeCertificate(agentId))?.certificate;
    if (!active || active.cert_id !== lc.data.cert_id || Date.parse(active.valid_to) <= Date.now()) return;
    const level = await enforcement.agentLevel(agentId);
    if (level === 'killed' || level === 'quarantined') return;
    const evidence = await db.prepare(`SELECT r.record_id, r.ts FROM ledger_record r
      JOIN agent_instance i ON i.id = jsonb_extract_path_text(r.data::jsonb, 'instance_id') AND i.agent_id = r.agent_id
      WHERE r.agent_id = ? AND r.cert_id = ? AND r.kind = 'transaction' AND i.revoked_at IS NULL AND i.version = ?
        AND jsonb_extract_path_text(r.data::jsonb, 'action_type') IN ('llm_call', 'tool_call')
        AND COALESCE(jsonb_extract_path_text(r.data::jsonb, 'error_code'), '') NOT IN (${GATEWAY_AUTH_ERRORS.map(() => '?').join(', ')})
      ORDER BY r.seq ASC LIMIT 1`).get(agentId, active.cert_id, active.version, ...GATEWAY_AUTH_ERRORS) as { record_id: string; ts: string } | undefined;
    if (!evidence) return;
    await move(lc, 'monitor', 'passed', 'system:gateway', { record_id: evidence.record_id, first_verified_at: evidence.ts, rollout: lc.data.deploy?.mode }, 'in_progress');
  });
}

export async function attest(agentId: string, p: Principal, input: { purpose_unchanged: boolean; manifest_minimal: boolean; owner_accountable: boolean; note?: string }) {
  const agent = (await getAgent(agentId));
  if (agent.owner !== p.id) throw forbidden('BP-6-S7', 'the owner attests');
  const active = (await activeCertificate(agent.id));
  if (!active) throw new PolicyError('BP-6-S7', 'no active seal to re-attest', 409);
  if (!(input.purpose_unchanged && input.manifest_minimal && input.owner_accountable)) {
    throw new PolicyError('BP-6-S7', 'a change in purpose, manifest or accountability needs a change request, not an attestation', 422);
  }
  const content = { ...input, cert_id: active.certificate.cert_id, version: active.certificate.version };
  const hash = sha256(canonicalize(content));
  const id = newId('evt').replace('evt_', 'att_');
  (await db.prepare('INSERT INTO attestation (id, agent_id, type, signer, content, content_hash, signed_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, agent.id, 're_attestation', p.id, JSON.stringify(content), hash, nowIso()));
  (await ledger.append({ kind: 'decision', agent_id: agent.id, cert_id: active.certificate.cert_id, data: { event: 'attestation.signed', attestation_id: id, type: 're_attestation', content_sha256: hash, signer: p.id } }));
  // Renewal (BP 4.3): inside the 30-day window an attestation renews the seal with the same manifest.
  const daysLeft = (Date.parse(active.certificate.valid_to) - Date.now()) / DAY;
  let renewed: string | null = null;
  if (daysLeft <= 30) {
    const c = active.certificate;
    const manifest: SealInput = { models: c.models, tools: c.tools, data_classes: c.data_classes, hitl: c.hitl, limits: c.limits, environments: c.environments, tags: c.tags, ai_disclosure: c.ai_disclosure };
    const issued = (await signSeal(agent.id, manifest, { approvers: [...c.approvers, { user: `${p.id} (re-attestation)`, at: nowIso() }], evidence_refs: { ...(c.evidence_refs ?? {}), attestation_sha256: hash }, regulatory_category: c.regulatory_category ?? 'unclassified', minor: true, actor: p.id }));
    renewed = issued.certificate.cert_id;
    hub.publish('bundle', { reason: 'certificate.renewed', cert_id: renewed });
  }
  return { attestation_id: id, content_sha256: hash, renewed_cert_id: renewed };
}

export async function requestChange(agentId: string, p: Principal, input: { kind: 'minor' | 'major'; manifest?: SealInput; reason: string }) {
  const agent = (await getAgent(agentId));
  (await assertOwnerSide(agent, p));
  if ((await forAgent(agent.id)).some((l) => l.status === 'in_progress')) throw new PolicyError('BP-6-S7', 'a lifecycle is already in progress for this agent', 409);
  if (!(await activeCertificate(agent.id))) throw new PolicyError('BP-6-S7', 'changes apply to a sealed agent', 409);
  if (!input.reason?.trim()) throw invalid('describe the change');
  const prevLc = (await forAgent(agent.id))[0]!;
  const manifest = input.manifest ?? prevLc.data.manifest;
  if (input.manifest) (await validateSeal(agent, input.manifest));
  // BP 6 Stage 7 change table: minor (prompt, config, model version) re-runs tests; major
  // (new model family, tool, data class, higher autonomy) goes back to Classify.
  const lc = (await start(agent, prevLc.data.intake, p, input.kind, manifest));
  (await tx(async () => {
    if (input.kind === 'minor') {
      const cls = (await classificationOf(prevLc.id));
      if (cls) (await db.prepare('INSERT INTO classification (lifecycle_id, factors, score, tier, regulatory_category, frameworks, reasons, overrides, confirmed_by, confirmed_at) SELECT ?, factors, score, tier, regulatory_category, frameworks, reasons, overrides, confirmed_by, confirmed_at FROM classification WHERE lifecycle_id = ?').run(lc.id, prevLc.id));
      (await move(lc, 'test', 'skipped', p.id, { change: 'minor', reason: input.reason }));
    } else {
      (await writeClassification(lc, {}, null));
      (await move(lc, 'classify', 'skipped', p.id, { change: 'major', reason: input.reason }));
    }
  }));
  return (await view(lc.id));
}

// --- Stage 8: Retire ----------------------------------------------------------------------------

export async function requestRetire(agentId: string, p: Principal, reason: string) {
  const agent = (await getAgent(agentId));
  if (agent.owner !== p.id && !p.roles.includes('security_officer')) throw forbidden('BP-6-S8', 'the owner or Security requests retirement');
  if (agent.status === 'retired') throw new PolicyError('BP-6-S8', 'agent is already retired', 409);
  if (!reason?.trim()) throw invalid('a reason is required');
  return (await approvals.create({
    type: 'retirement', agent_id: agent.id, subject_ref: agent.id, tier: agent.tier, created_by: p.id, sla_ms: 5 * DAY,
    title: `Retirement · ${agent.handle}`, summary: reason,
    pack: { agent: { id: agent.id, handle: agent.handle, tier: agent.tier }, reason, certificate: (await activeCertificate(agent.id))?.certificate.cert_id ?? null },
    // BP 6 Stage 8: owner and Security sign the decommission attestation.
    slots: [{ slot: 'owner', label: 'Owner', roles: [], count: 1, owner_only: true }, { slot: 'security', label: 'Security', roles: ['security_officer'], count: 1 }],
  }));
}

approvals.onDecision('retirement', async (req, outcome) => {
  if (outcome !== 'approved' || !req.agent_id) return;
  const agent = (await getAgent(req.agent_id));
  const certs = (await db.prepare('SELECT id, version, status FROM certificate WHERE agent_id = ?').all(agent.id));
  const now = Math.floor(Date.now() / 1000);
  (await tx(async () => {
    (await db.prepare("UPDATE certificate SET status = 'retired' WHERE agent_id = ? AND status = 'active'").run(agent.id));
    for (const t of (await db.prepare('SELECT jti, exp FROM issued_token WHERE agent_id = ? AND exp > ?').all(agent.id, now)) as { jti: string; exp: number }[]) (await db.prepare('INSERT INTO revoked_jti (jti, exp) VALUES (?, ?) ON CONFLICT DO NOTHING').run(t.jti, t.exp));
    (await db.prepare("UPDATE agent_instance SET state = 'retired' WHERE agent_id = ?").run(agent.id));
    (await db.prepare("UPDATE agent SET status = 'retired' WHERE id = ?").run(agent.id));
    (await db.prepare("UPDATE lifecycle SET status = 'retired', stage = 'retire', updated_at = ? WHERE agent_id = ? AND status IN ('complete', 'in_progress')").run(nowIso(), agent.id));
    const toolSecrets = ((await db.prepare('SELECT secret_id FROM tool WHERE secret_id IS NOT NULL').all()) as { secret_id: string }[]).map((r) => r.secret_id);
    (await markRotationDue(toolSecrets, `retirement of ${agent.handle}`));
    const pack = { agent, certificates: certs, approvals: (req.decisions ?? []).map((d) => ({ approver: d.approver, slot: d.slot, ts: d.ts })), retired_at: nowIso(), reason: req.summary };
    const hash = sha256(canonicalize(pack));
    (await db.prepare('INSERT INTO attestation (id, agent_id, type, signer, content, content_hash, signed_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(newId('evt').replace('evt_', 'att_'), agent.id, 'decommission', (req.decisions ?? []).map((d) => d.approver).join(','), JSON.stringify(pack), hash, nowIso()));
    (await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'agent.retired', decommission_pack_sha256: hash, approval_id: req.id, note: 'Agent ID is never reused' } }));
  }));
  hub.publish('bundle', { reason: 'agent.retired', agent_id: agent.id });
  (await enqueue('ci.upsert', correlation('agent', agent.id), (await ciPayload(agent.id, 'Retired'))));
});

// Quarantine release goes through approvals (BP 7.2: T1 needs Owner + Security + Risk, two-person).
export async function requestRelease(agentId: string, p: Principal, reason: string) {
  const agent = (await getAgent(agentId));
  if ((await enforcement.agentLevel(agent.id)) === 'active') throw new PolicyError('BP-5.4', 'nothing to release', 409);
  if ((await enforcement.agentLevel(agent.id)) === 'killed') throw new PolicyError('RB-INV-08', 'a kill is never lifted', 409);
  if (!reason?.trim()) throw invalid('a reason is required');
  const owner: approvals.Slot = { slot: 'owner', label: 'Owner', roles: [], count: 1, owner_only: true };
  const security: approvals.Slot = { slot: 'security', label: 'Security', roles: ['security_officer'], count: 1 };
  const risk: approvals.Slot = { slot: 'risk', label: 'Risk', roles: ['risk_officer'], count: 1 };
  const slots = { T4: [owner], T3: [owner, security], T2: [owner, security], T1: [owner, security, risk] }[agent.tier];
  return (await approvals.create({
    type: 'quarantine_release', agent_id: agent.id, subject_ref: agent.id, tier: agent.tier, created_by: p.id, sla_ms: DAY,
    title: `Quarantine release · ${agent.tier} · ${agent.handle}`, summary: reason,
    pack: { agent: { id: agent.id, handle: agent.handle, tier: agent.tier }, states: (await enforcement.statesFor(agent.id)), reason }, slots,
  }));
}

approvals.onDecision('quarantine_release', async (req, outcome) => {
  if (outcome !== 'approved' || !req.agent_id) return;
  const approvers = (req.decisions ?? []).map((d) => d.approver).join(' + ');
  for (const s of (await enforcement.statesFor(req.agent_id))) {
    if (s.level === 'quarantined' || s.level === 'step_up' || s.level === 'throttled') {
      const [kind, ref] = s.scope_key.split(':') as [string, string];
      (await enforcement.applyLadder(
        { agentId: req.agent_id, scope: kind as 'agent' | 'version' | 'instance', version: kind === 'version' ? ref.split('@')[1] : undefined, instanceId: kind === 'instance' ? ref : undefined },
        'release',
        { actor: approvers, reason: `approval ${req.id}: ${req.summary}` },
      ));
    }
  }
});

// --- Background: re-attestation reminders, expiry suspension ------------------------------------

export async function sweep() {
  const deployments = await db.prepare("SELECT DISTINCT agent_id FROM lifecycle WHERE stage = 'deploy' AND status = 'in_progress'").all() as { agent_id: string }[];
  for (const deployment of deployments) await monitorConnectedAgent(deployment.agent_id);
  for (const c of (await db.prepare("SELECT c.id, c.agent_id, c.valid_to, a.owner, a.handle FROM certificate c JOIN agent a ON a.id = c.agent_id WHERE c.status = 'active'").all()) as { id: string; agent_id: string; valid_to: string; owner: string; handle: string }[]) {
    const left = (Date.parse(c.valid_to) - Date.now()) / DAY;
    if (left <= 0) {
      // RB-KILL-11: an expired seal suspends the agent (same effect as quarantine).
      if ((await enforcement.agentLevel(c.agent_id)) === 'active') (await enforcement.applyLadder({ agentId: c.agent_id }, 'quarantine', { actor: 'system:expiry', reason: 'seal expired without re-attestation', rule_id: 'RB-KILL-11', automatic: true }));
      continue;
    }
    for (const mark of [30, 14, 7]) {
      if (left <= mark && left > mark - 1) {
        const key = `reattest:${c.id}:${mark}`;
        if (!(await db.prepare('SELECT 1 FROM notification WHERE kind = ? AND link = ?').get(key, `/agents/${c.agent_id}`))) (await notify(c.owner, key, `${c.handle}: seal expires in ${Math.ceil(left)} days; re-attest to renew`, `/agents/${c.agent_id}`));
      }
    }
  }
}

async function ciPayload(agentId: string, installStatus: 'On order' | 'Installed' | 'Operational' | 'Non-operational' | 'Retired') {
  const a = (await getAgent(agentId));
  const c = (await activeCertificate(agentId))?.certificate;
  return { agent_id: a.id, handle: a.handle, name: a.name, tier: a.tier, autonomy_level: a.autonomy_level, owner: a.owner, certificate_status: c ? 'active' : a.status, certificate_expiry: c?.valid_to ?? null, regulatory_category: c?.regulatory_category ?? null, install_status: installStatus };
}

// --- View ---------------------------------------------------------------------------------------

export async function view(lcId: string) {
  const lc = (await get(lcId));
  const agent = (await getAgent(lc.agent_id));
  const stages = (await db.prepare('SELECT stage, outcome, actor, gate, entered_at, exited_at FROM stage_record WHERE lifecycle_id = ? ORDER BY exited_at').all(lc.id)) as { gate: string }[];
  const tests = ((await db.prepare('SELECT id, status, suites, report_sha256, actor, created_at FROM test_run WHERE lifecycle_id = ? ORDER BY created_at DESC').all(lc.id)) as { suites: string }[]).map((t) => ({ ...t, suites: JSON.parse(t.suites) }));
  const gate = lc.stage === 'propose' ? (await proposeGate(lc)) : lc.stage === 'assess' ? (await assessGate(lc)) : null;
  const deploy = lc.data.deploy && lc.data.cert_id ? { ...lc.data.deploy, stats: (await deployStats(lc.data.cert_id, lc.data.deploy.mode_since)), days_in_mode: (Date.now() - Date.parse(lc.data.deploy.mode_since)) / DAY } : null;
  return {
    lifecycle: lc,
    agent: { id: agent.id, handle: agent.handle, kind: agent.kind, tier: agent.tier, owner: agent.owner, status: agent.status },
    stages: stages.map((s) => ({ ...s, gate: JSON.parse(s.gate) })),
    gate,
    classification: (await classificationOf(lc.id)),
    assessments: (await assessments(lc.id)),
    required_assessments: requiredAssessments(agent.tier),
    gaps: (await gapsOf(lc.id)),
    tests,
    approval: lc.data.approval_id ? (await approvals.get(lc.data.approval_id)) : null,
    deploy,
  };
}

export { current as currentLifecycle };
export type { Role };
