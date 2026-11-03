import { newId } from '@signet/core';
import * as approvals from './approvals';
import { db, nowIso } from './db';
import * as enforcement from './enforcement';
import { PolicyError, invalid } from './errors';
import * as ledger from './ledger';
import { tenant } from './tenant';

// Runtime human-in-the-loop (BP 5.2 step 10, 7.4). The gateway parks the action and asks for a person.
// Approver groups from the seal (or the tenant rules) map to roles; "approve for this session" leaves
// a grant every gateway node honours; a timeout is a rejection (RB-INV-11).

export interface HitlInput {
  agent_id: string;
  cert_id: string;
  session_id: string;
  action_key: string; // e.g. mcp://orders.issue_refund or llm
  args_masked: unknown; // DLP-masked arguments, never raw values
  rule_ids: string[];
  approver_groups: string[];
  reasons: string[];
  request_id: string;
  node_id: string;
  caller_user_id: string | null;
}

const SESSION_GRANT_HOURS = 8;

export async function open(input: HitlInput) {
  if (!input.agent_id || !input.action_key) throw invalid('agent_id and action_key are required');
  const grant = (await approvals.hitlGrant(input.session_id, input.agent_id, input.action_key));
  if (grant) return { status: 'approved', grant: true, approval_id: grant.request_id };
  const agent = (await db.prepare('SELECT handle, tier FROM agent WHERE id = ?').get(input.agent_id)) as { handle: string; tier: 'T1' | 'T2' | 'T3' | 'T4' } | undefined;
  if (!agent) throw invalid('unknown agent');
  const groups = input.approver_groups.length ? input.approver_groups : ['owner-approvers'];
  const map = tenant.settings.approver_groups;
  const slots: approvals.Slot[] = [...new Set(groups)].map((g) => {
    const m = map[g] ?? map['owner-approvers']!;
    return { slot: g, label: g, roles: m.roles, count: m.count ?? 1, owner_allowed: m.owner ?? false };
  });
  const req = (await approvals.create({
    type: 'runtime_hitl',
    agent_id: input.agent_id,
    subject_ref: input.request_id,
    tier: agent.tier,
    created_by: `gateway:${input.node_id}`,
    sla_ms: tenant.settings.hitl_wait_seconds * 1000,
    title: `Runtime approval · ${agent.handle} · ${input.action_key.replace(/^(mcp|http):\/\//, '')}`,
    summary: input.reasons.join('; ') || input.rule_ids.join(', '),
    pack: { action: input.action_key, args: input.args_masked, rules: input.rule_ids, reasons: input.reasons, session_id: input.session_id, caller_user_id: input.caller_user_id, cert_id: input.cert_id },
    slots,
    data: { session_id: input.session_id, action_key: input.action_key },
  }));
  return { status: 'pending', approval_id: req.id, expires_at: req.sla_due };
}

export async function status(id: string) {
  const r = (await approvals.get(id));
  return { approval_id: r.id, status: r.status, outcome: r.outcome, decided_at: r.decided_at, approvers: (r.decisions ?? []).map((d) => ({ approver: d.approver, decision: d.decision })) };
}

// Async resubmission: an approved runtime approval is used once, by the same agent, for the same action.
export async function consume(id: string, input: { agent_id: string; action_key: string; session_id: string }) {
  const r = (await approvals.get(id));
  const d = r.data as { action_key?: string; session_id?: string; consumed_at?: string };
  if (r.type !== 'runtime_hitl') throw new PolicyError('BP-7.4', 'not a runtime approval', 409);
  if (r.status !== 'approved') throw new PolicyError('BP-7.4', `approval is ${r.status}`, 409);
  if (r.agent_id !== input.agent_id || d.action_key !== input.action_key) throw new PolicyError('BP-7.4', 'approval was given for a different agent or action', 409);
  if (d.consumed_at) throw new PolicyError('BP-7.4', 'approval was already used', 409);
  (await db.prepare('UPDATE approval_request SET data = ? WHERE id = ?').run(JSON.stringify({ ...d, consumed_at: nowIso(), consumed_session: input.session_id }), id));
  (await ledger.append({ kind: 'decision', agent_id: r.agent_id, data: { event: 'hitl.consumed', approval_id: id, action_key: input.action_key, session_id: input.session_id } }));
  return { ok: true, approvers: (r.decisions ?? []).map((x) => x.approver) };
}

approvals.onDecision('runtime_hitl', async (req, outcome, p, decision) => {
  const d = req.data as { session_id: string; action_key: string };
  if (outcome === 'approved' && decision === 'approve_session' && req.agent_id) {
    (await db.prepare('INSERT INTO hitl_grant (session_id, agent_id, action_key, request_id, expires_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (session_id, agent_id, action_key) DO UPDATE SET request_id = EXCLUDED.request_id, expires_at = EXCLUDED.expires_at').run(
      d.session_id, req.agent_id, d.action_key, req.id, new Date(Date.now() + SESSION_GRANT_HOURS * 3_600_000).toISOString(),
    ));
    (await ledger.append({ kind: 'decision', agent_id: req.agent_id, data: { event: 'hitl.session_grant', approval_id: req.id, session_id: d.session_id, action_key: d.action_key, hours: SESSION_GRANT_HOURS } }));
  }
  if (outcome === 'rejected' && decision === 'reject_quarantine' && req.agent_id) {
    (await enforcement.applyLadder({ agentId: req.agent_id }, 'quarantine', { actor: p?.id ?? 'approver', reason: `runtime approval ${req.id} rejected with quarantine` }));
  }
});

export const newRequestId = () => newId('req');
export const now = nowIso;
