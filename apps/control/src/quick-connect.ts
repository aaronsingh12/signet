import { request } from '@signet/core';
import * as approvals from './approvals';
import { createDeploymentCredential } from './deployment-identity';
import { invalid } from './errors';
import { singleOperator, type Principal } from './rbac';
import { getAgent, registerAgent } from './registry';
import { tenant } from './tenant';
import * as workflow from './workflow';
import { gatewayAddress } from './connection-settings';

// One form from registration to a working key, for agents that only call the model. Nothing is
// invented on the admin's behalf: the classifier decides the tier, T3 questionnaire answers come from
// the admin, and T1/T2 agents go to the full lifecycle, whose evidence cannot be skipped.

const AUDIENCES = ['internal', 'customers', 'public'];
const DATA = ['personal', 'financial_account', 'confidential_doc', 'source_code'];
const REVERSIBILITY = ['yes', 'partly', 'no'];
const envName = () => process.env.SIGNET_ENV ?? 'dev';

export type QuickConnectResult =
  | { state: 'connected'; agent_id: string; lifecycle_id: string; tier: string; deployment_credential: string; expires_at: string; rollout: string; open_gaps: string[] }
  | { state: 'needs_answers'; agent_id: string; lifecycle_id: string; tier: string; questions: { id: string; text: string }[] }
  | { state: 'needs_review' | 'awaiting_approval'; agent_id: string; lifecycle_id: string; tier: string; reason: string };

export async function start(body: Record<string, unknown>, p: Principal): Promise<QuickConnectResult> {
  const name = String(body.name ?? '').trim();
  const handle = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63).replace(/-$/, '');
  if (!handle) throw invalid('name the agent');
  if (String(body.purpose ?? '').trim().length < 10) throw invalid('describe the purpose in at least 10 characters');
  const users = Array.isArray(body.users_affected) ? body.users_affected.map(String) : [];
  const data = Array.isArray(body.data_touched) ? body.data_touched.map(String) : [];
  if (!users.length || users.some((u) => !AUDIENCES.includes(u))) throw invalid('choose who the agent affects');
  if (data.some((d) => !DATA.includes(d))) throw invalid('this data type needs the full registration');
  const reversibility = String(body.reversibility ?? 'partly');
  if (!REVERSIBILITY.includes(reversibility)) throw invalid('reversibility must be yes, partly or no');
  const agent = await registerAgent({ handle, name, purpose: String(body.purpose ?? ''), sponsor: String(body.sponsor ?? '').trim() || p.id, autonomy_level: 'L2', kind: 'self_hosted', connection_method: 'rest' } as never, p);
  // From here the agent exists: a later failure sends the admin to its page, where it can be finished.
  try {
  const lc = await workflow.start(agent, { users_affected: users, data_touched: data, reversibility, decisions_about_individuals: body.decisions_about_individuals === true, individual_domains: [], planned_tools: [] } as never, p);
  await workflow.setManifest(lc.id, {
    models: tenant.settings.catalogue.slice(0, 1).map((m) => ({ model: m.model, region: m.region })),
    data_classes: { prompt: data, forbidden: ['payment_card'] },
    limits: { rpm: 60, tokens_per_day: 200_000, usd_per_day: 10 },
    environments: [envName()],
  } as never, p);
  await workflow.submitPropose(lc.id, p);
  await workflow.classify(lc.id, p, { confirm: true });
  return await advance(agent.id, lc.id, p);
  } catch (e) {
    const current = (await workflow.forAgent(agent.id))[0];
    return { state: 'needs_review', agent_id: agent.id, lifecycle_id: current?.id ?? '', tier: (await getAgent(agent.id)).tier ?? '', reason: `quick connect stopped: ${(e as Error).message}` };
  }
}

export async function advance(agentId: string, lifecycleId: string, p: Principal, answers?: Record<string, string>): Promise<QuickConnectResult> {
  const ids = { agent_id: agentId, lifecycle_id: lifecycleId };
  for (const a of Object.values(answers ?? {})) if (!['yes', 'partial', 'no', 'na'].includes(a)) throw invalid('answers must be yes, partial, no or na');
  const lc = await workflow.get(lifecycleId);
  if (lc.agent_id !== agentId) throw invalid('lifecycle does not belong to this agent');
  const tier = (await getAgent(agentId)).tier ?? '';
  const full = (reason: string): QuickConnectResult => ({ state: 'needs_review', ...ids, tier, reason });
  if (lc.stage !== 'assess') return full(`the lifecycle is at ${lc.stage}; continue it from the agent page`);
  if (tier === 'T1' || tier === 'T2') return full(`classified ${tier}: this risk level needs a threat model, an impact assessment and test evidence`);

  if (tier === 'T3') {
    const asm = ((await workflow.assessments(lc.id)) as unknown as { type: string; content: { questions: { id: string; text: string }[]; answers: Record<string, { answer: string; note?: string }> } }[]).find((a) => a.type === 'questionnaire')!;
    const merged = Object.fromEntries(Object.entries(asm.content.answers).map(([id, a]) => [id, { ...a, answer: answers?.[id] ?? a.answer }]));
    const unanswered = asm.content.questions.filter((q) => !['yes', 'partial', 'no', 'na'].includes(merged[q.id]?.answer ?? ''));
    if (unanswered.length) return { state: 'needs_answers', ...ids, tier, questions: unanswered.map((q) => ({ id: q.id, text: q.text })) };
    await workflow.saveAssessment(lc.id, 'questionnaire', { ...asm.content, answers: merged }, true, p);
  }
  try {
    await workflow.submitAssess(lc.id, p);
  } catch (e) {
    return full(`the assessment found open gaps: ${(e as Error).message}`);
  }
  const tests = await workflow.runTests(lc.id, p, {});
  if (!tests.passed) return full('baseline tests failed; see the findings on the agent page');
  const after = await workflow.get(lc.id);
  if (after.stage === 'approve') {
    if (!singleOperator(p)) return { state: 'awaiting_approval', ...ids, tier, reason: 'waiting for the approvers in My Approvals' };
    await approvals.decide(after.data.approval_id!, p, { decision: 'approve' });
  }
  const credential = await createDeploymentCredential(agentId, p, envName());
  return { state: 'connected', ...ids, tier, deployment_credential: credential.deployment_credential, expires_at: credential.expires_at, rollout: (await workflow.get(lc.id)).data.deploy?.mode ?? 'shadow', open_gaps: ((await workflow.gapsOf(lc.id)) as { title: string; status: string }[]).filter((g) => g.status === 'open').map((g) => g.title) };
}

const HINTS: Record<string, string> = {
  invalid_api_key: 'The key was refused. Check it was copied whole and has not been revoked or expired.',
  rate_limited: 'The per-minute limit was reached. Wait a minute or raise the limit.',
  token_budget_exhausted: 'The daily token budget is used up.',
  cost_budget_exhausted: 'The daily cost budget is used up.',
  wrong_environment: 'The approval does not cover the gateway environment (SIGNET_ENV).',
  ledger_unavailable: 'The gateway could not write its evidence record. Check the control plane and database.',
  identity_unavailable: 'The gateway could not reach the control plane to check the key.',
};

/** One real request through the public gateway, so the admin sees what the agent will see. */
export async function testCall(credential: unknown): Promise<{ ok: boolean; status: number; reply?: string; code?: string; message?: string; hint?: string; record_id?: string }> {
  if (typeof credential !== 'string' || !/^sdc_[A-Za-z0-9_-]+$/.test(credential)) throw invalid('paste a deployment credential (it starts with sdc_)');
  const base = await gatewayAddress();
  let r;
  try {
    // Test with a model this agent's seal grants: any other would count as an out-of-manifest attempt.
    const listed = await request(`${base.replace(/\/+$/, '')}/v1/models`, { headers: { authorization: `Bearer ${credential}` }, timeoutMs: 10_000 });
    const model = (listed.ok ? listed.json<{ data?: { id: string }[] }>().data?.[0]?.id : undefined) ?? tenant.settings.catalogue[0]!.model;
    r = await request(`${base.replace(/\/+$/, '')}/v1/chat/completions`, {
      method: 'POST', timeoutMs: 60_000,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${credential}` },
      body: JSON.stringify({ model, max_tokens: 200, messages: [{ role: 'user', content: 'Connection test: reply with the single word OK.' }] }),
    });
  } catch (e) {
    return { ok: false, status: 0, code: 'gateway_unreachable', message: (e as Error).message, hint: `Signet could not reach the gateway at ${base}. Check Hosted Signet addresses in the connection setup.` };
  }
  const record_id = r.headers['x-signet-record-id'];
  let body: { choices?: { message?: { content?: string } }[]; error?: { code?: string; message?: string } } = {};
  try { body = r.json(); } catch { /* not JSON */ }
  if (r.ok) return { ok: true, status: r.status, reply: body.choices?.[0]?.message?.content ?? '', record_id };
  const code = body.error?.code ?? 'unknown';
  return { ok: false, status: r.status, code, message: body.error?.message ?? `gateway returned ${r.status}`, hint: HINTS[code] ?? 'Open this request under Activity history for the full check list.', record_id };
}
