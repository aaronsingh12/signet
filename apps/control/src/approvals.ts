import { canonicalize, newId, sha256, type Tier } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import * as hub from './hub';
import * as ledger from './ledger';
import { notify, notifyRoles } from './notify';
import type { Principal, Role } from './rbac';

// Approvals engine (BP 7). One engine for every decision type: certificate approvals, risk
// acceptances, runtime human-in-the-loop holds, quarantine releases and retirements. Every decision
// records the approver, the slot they filled, their authentication strength and the hash of the
// Approval Pack they saw, so nobody can later claim a different version was shown (BP 7.3).

export type ApprovalType = 'certificate' | 'risk_acceptance' | 'runtime_hitl' | 'quarantine_release' | 'retirement';
export type Decision = 'approve' | 'approve_session' | 'reject' | 'reject_quarantine' | 'send_back';
export type Outcome = 'approved' | 'rejected' | 'sent_back' | 'expired';

export interface Slot {
  slot: string;
  label: string;
  roles: Role[];
  count: number;
  owner_only?: boolean; // the agent's accountable owner signs this slot
  owner_allowed?: boolean; // runtime approvals: the owner may also fill this slot
}

export interface ApprovalRequest {
  id: string;
  type: ApprovalType;
  agent_id: string | null;
  subject_ref: string;
  title: string;
  summary: string;
  pack: Record<string, unknown>;
  pack_hash: string;
  slots: Slot[];
  tier: Tier | null;
  status: 'pending' | 'approved' | 'rejected' | 'sent_back' | 'expired' | 'cancelled';
  outcome: string | null;
  sla_due: string;
  escalation: number;
  created_by: string;
  created_at: string;
  decided_at: string | null;
  data: Record<string, unknown>;
  decisions?: DecisionRow[];
}

interface DecisionRow {
  id: string;
  approver: string;
  slot: string;
  delegate_of: string | null;
  decision: Decision;
  comment: string | null;
  conditions: string | null;
  auth_strength: string;
  pack_hash: string;
  ts: string;
}

type Row = Omit<ApprovalRequest, 'pack' | 'slots' | 'data'> & { pack: string; slots: string; data: string };
const parse = (r: Row): ApprovalRequest => ({ ...r, pack: JSON.parse(r.pack), slots: JSON.parse(r.slots), data: JSON.parse(r.data) });

const STEP_UP_SECONDS = 300; // BP 7.3: fresh MFA within 5 minutes for T1/T2 decisions and kill reversals

type Handler = (req: ApprovalRequest, outcome: Outcome, p: Principal | null, decision?: Decision) => void;
const handlers = new Map<ApprovalType, Handler>();
export const onDecision = (type: ApprovalType, fn: Handler) => handlers.set(type, fn);

export interface CreateInput {
  type: ApprovalType;
  agent_id: string | null;
  subject_ref: string;
  title: string;
  summary: string;
  pack: Record<string, unknown>;
  slots: Slot[];
  tier: Tier | null;
  sla_ms: number;
  created_by: string;
  data?: Record<string, unknown>;
}

export function create(input: CreateInput): ApprovalRequest {
  if (!input.slots.length) throw invalid('an approval needs at least one slot');
  const id = newId('evt').replace('evt_', 'apr_');
  const packHash = sha256(canonicalize(input.pack));
  const now = Date.now();
  tx(() => {
    db.prepare(
      'INSERT INTO approval_request (id, type, agent_id, subject_ref, title, summary, pack, pack_hash, slots, tier, status, sla_due, created_by, created_at, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(id, input.type, input.agent_id, input.subject_ref, input.title, input.summary, JSON.stringify(input.pack), packHash, JSON.stringify(input.slots), input.tier, 'pending', new Date(now + input.sla_ms).toISOString(), input.created_by, new Date(now).toISOString(), JSON.stringify(input.data ?? {}));
    ledger.append({ kind: 'decision', agent_id: input.agent_id, data: { event: 'approval.requested', approval_id: id, type: input.type, subject_ref: input.subject_ref, pack_sha256: packHash, slots: input.slots.map((s) => `${s.slot}×${s.count}`), sla_due: new Date(now + input.sla_ms).toISOString(), requested_by: input.created_by } });
  });
  const link = input.type === 'runtime_hitl' ? `/m/approvals/${id}` : `/approvals?id=${id}`;
  for (const s of input.slots) {
    if (s.owner_only) {
      const owner = input.agent_id ? (db.prepare('SELECT owner FROM agent WHERE id = ?').get(input.agent_id) as { owner: string } | undefined)?.owner : undefined;
      if (owner) notify(owner, 'approval', input.title, link);
    } else notifyRoles(s.roles, 'approval', input.title, link);
  }
  return get(id);
}

export function get(id: string): ApprovalRequest {
  const r = db.prepare('SELECT * FROM approval_request WHERE id = ?').get(id) as Row | undefined;
  if (!r) throw notFound(`approval ${id}`);
  const req = parse(r);
  req.decisions = db.prepare('SELECT id, approver, slot, delegate_of, decision, comment, conditions, auth_strength, pack_hash, ts FROM approval_decision WHERE request_id = ? ORDER BY ts').all(id) as unknown as DecisionRow[];
  return req;
}

interface AgentFacts {
  owner: string;
  created_by: string;
  team: string[];
}

function agentFacts(agentId: string | null): AgentFacts | null {
  if (!agentId) return null;
  const a = db.prepare('SELECT owner, created_by FROM agent WHERE id = ?').get(agentId) as { owner: string; created_by: string } | undefined;
  if (!a) return null;
  const team = (db.prepare('SELECT user FROM agent_team_member WHERE agent_id = ?').all(agentId) as { user: string }[]).map((t) => t.user);
  return { ...a, team };
}

function filled(req: ApprovalRequest) {
  const counts: Record<string, number> = {};
  for (const d of req.decisions ?? []) if (d.decision === 'approve' || d.decision === 'approve_session') counts[d.slot] = (counts[d.slot] ?? 0) + 1;
  return counts;
}

// Slots this person may fill now. Separation of duties (RB-INV-09): the proposer, owner and build
// team can never fill an independent slot; the owner fills only the owner slot.
export function eligibleSlots(req: ApprovalRequest, p: Principal): Slot[] {
  if (req.status !== 'pending' || p.kind !== 'human') return [];
  if ((req.decisions ?? []).some((d) => d.approver === p.id)) return [];
  const facts = agentFacts(req.agent_id);
  const counts = filled(req);
  return req.slots.filter((s) => {
    if ((counts[s.slot] ?? 0) >= s.count) return false;
    if (s.owner_only) return !!facts && facts.owner === p.id;
    if (s.owner_allowed && facts && facts.owner === p.id) return true;
    if (facts && [facts.owner, facts.created_by, ...facts.team].includes(p.id)) return false;
    return s.roles.some((r) => p.roles.includes(r));
  });
}

function activeDelegator(p: Principal): string | null {
  const now = nowIso();
  const d = db.prepare('SELECT from_user FROM delegation WHERE to_user = ? AND from_date <= ? AND to_date >= ? ORDER BY created_at DESC LIMIT 1').get(p.id, now, now) as { from_user: string } | undefined;
  return d?.from_user ?? null;
}

export interface DecideInput {
  decision: Decision;
  comment?: string;
  conditions?: string;
  slot?: string;
}

export function decide(id: string, p: Principal, input: DecideInput): ApprovalRequest {
  const req = get(id);
  if (req.status !== 'pending') throw new PolicyError('BP-7', `this approval is already ${req.status}`, 409);
  if (Date.parse(req.sla_due) < Date.now() && req.type === 'runtime_hitl') throw new PolicyError('RB-INV-11', 'this runtime approval timed out and was rejected', 409);
  if (!['approve', 'approve_session', 'reject', 'reject_quarantine', 'send_back'].includes(input.decision)) throw invalid('unknown decision');
  if ((input.decision === 'approve_session' || input.decision === 'reject_quarantine') && req.type !== 'runtime_hitl') throw invalid(`${input.decision} applies to runtime approvals only`);
  if (input.decision === 'send_back' && req.type !== 'certificate') throw invalid('send_back applies to certificate approvals');
  if (input.decision !== 'approve' && input.decision !== 'approve_session' && !input.comment?.trim()) throw invalid('a reason is required to reject or send back');
  const slots = eligibleSlots(req, p);
  const slot = input.slot ? slots.find((s) => s.slot === input.slot) : slots[0];
  if (!slot) {
    const facts = agentFacts(req.agent_id);
    if (facts && [facts.owner, facts.created_by, ...facts.team].includes(p.id) && !req.slots.some((s) => s.owner_only && facts.owner === p.id)) {
      throw forbidden('RB-INV-09', `${p.id} proposed, owns or builds this agent and cannot approve it`);
    }
    throw forbidden('BP-7.2', 'you hold no open approval slot on this request');
  }
  // Step-up (BP 7.3): T1/T2 decisions need MFA at the IdP within the last 5 minutes.
  const stepUp = (req.tier === 'T1' || req.tier === 'T2') && req.type !== 'runtime_hitl';
  const age = p.auth_time ? Math.floor(Date.now() / 1000) - p.auth_time : null;
  if (stepUp && (age === null || age > STEP_UP_SECONDS)) {
    throw new PolicyError('AUTH-STEP-UP', 'this decision needs a fresh sign-in (within 5 minutes) for a T1/T2 agent', 401, { reauth: true });
  }
  const auth = { method: p.auth, mfa: p.mfa, auth_age_s: age, step_up_required: stepUp };
  const decisionId = newId('evt').replace('evt_', 'dec_');
  let outcome: Outcome | null = null;
  tx(() => {
    db.prepare('INSERT INTO approval_decision (id, request_id, approver, slot, delegate_of, decision, comment, conditions, auth_strength, pack_hash, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      decisionId, id, p.id, slot.slot, activeDelegator(p), input.decision, input.comment ?? null, input.conditions ?? null, JSON.stringify(auth), req.pack_hash, nowIso(),
    );
    const after = get(id);
    if (input.decision === 'reject' || input.decision === 'reject_quarantine') outcome = 'rejected';
    else if (input.decision === 'send_back') outcome = 'sent_back';
    else {
      const counts = filled(after);
      if (after.slots.every((s) => (counts[s.slot] ?? 0) >= s.count)) outcome = 'approved';
    }
    ledger.append({
      kind: 'decision',
      agent_id: req.agent_id,
      data: { event: 'approval.decision', approval_id: id, type: req.type, decision: input.decision, slot: slot.slot, approver: p.id, conditions: input.conditions ?? null, comment: input.comment ?? null, pack_sha256: req.pack_hash, auth, complete: outcome },
    });
    if (outcome) {
      const status = outcome === 'approved' ? 'approved' : outcome === 'sent_back' ? 'sent_back' : 'rejected';
      db.prepare('UPDATE approval_request SET status = ?, outcome = ?, decided_at = ? WHERE id = ?').run(status, input.decision, nowIso(), id);
    }
  });
  const final = get(id);
  if (outcome) finish(final, outcome, p, input.decision);
  return final;
}

function finish(req: ApprovalRequest, outcome: Outcome, p: Principal | null, decision?: Decision) {
  if (req.type === 'runtime_hitl') hub.publish('hitl', { approval_id: req.id, status: req.status, decision: decision ?? outcome });
  const h = handlers.get(req.type);
  if (h) {
    try {
      h(req, outcome, p, decision);
    } catch (e) {
      console.error(`[control] approval handler for ${req.type} failed`, e);
    }
  }
}

export function cancel(id: string, actor: string, reason: string) {
  const req = get(id);
  if (req.status !== 'pending') return req;
  db.prepare("UPDATE approval_request SET status = 'cancelled', decided_at = ? WHERE id = ?").run(nowIso(), id);
  ledger.append({ kind: 'decision', agent_id: req.agent_id, data: { event: 'approval.cancelled', approval_id: id, actor, reason } });
  return get(id);
}

export function list(opts: { status?: string; type?: string; agent?: string; limit?: number }) {
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (opts.status) (where.push('status = ?'), args.push(opts.status));
  if (opts.type) (where.push('type = ?'), args.push(opts.type));
  if (opts.agent) (where.push('agent_id = ?'), args.push(opts.agent));
  args.push(opts.limit ?? 100);
  return (db.prepare(`SELECT * FROM approval_request ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC LIMIT ?`).all(...args) as unknown as Row[]).map(parse);
}

// My Approvals: pending requests with a slot this person can fill, plus ones delegated to them.
export function forMe(p: Principal) {
  return list({ status: 'pending', limit: 500 })
    .map((r) => ({ ...r, decisions: get(r.id).decisions }))
    .filter((r) => eligibleSlots(r, p).length > 0)
    .map((r) => ({ ...r, my_slots: eligibleSlots(r, p).map((s) => s.slot) }));
}

export function delegate(p: Principal, to: string, fromDate: string, toDate: string) {
  if (!to || to.toLowerCase() === p.id) throw invalid('delegate to someone else');
  if (!(Date.parse(fromDate) <= Date.parse(toDate))) throw invalid('date range is not valid');
  const id = newId('evt').replace('evt_', 'dlg_');
  db.prepare('INSERT INTO delegation (id, from_user, to_user, from_date, to_date, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, p.id, to.toLowerCase(), new Date(fromDate).toISOString(), new Date(toDate).toISOString(), nowIso());
  ledger.append({ kind: 'decision', data: { event: 'approval.delegated', from: p.id, to: to.toLowerCase(), from_date: fromDate, to_date: toDate } });
  notify(to.toLowerCase(), 'delegation', `${p.name} delegated approvals to you until ${toDate.slice(0, 10)}`, '/approvals');
  return { id };
}

// Escalation (BP 7.3): reminder at 50% of the SLA, escalation at 100%, governance flag at 200%.
// Runtime holds that pass their SLA are rejected, which is what a timeout means (RB-INV-11).
export function sweep() {
  const now = Date.now();
  for (const req of list({ status: 'pending', limit: 1000 })) {
    const start = Date.parse(req.created_at);
    const due = Date.parse(req.sla_due);
    const used = (now - start) / Math.max(1, due - start);
    if (req.type === 'runtime_hitl') {
      if (now > due) {
        db.prepare("UPDATE approval_request SET status = 'expired', outcome = 'timeout_reject', decided_at = ? WHERE id = ?").run(nowIso(), req.id);
        ledger.append({ kind: 'decision', agent_id: req.agent_id, data: { event: 'approval.expired', approval_id: req.id, rule_id: 'RB-INV-11', result: 'rejected on timeout' } });
        finish(get(req.id), 'expired', null);
      }
      continue;
    }
    const level = used >= 2 ? 3 : used >= 1 ? 2 : used >= 0.5 ? 1 : 0;
    if (level > req.escalation) {
      db.prepare('UPDATE approval_request SET escalation = ? WHERE id = ?').run(level, req.id);
      const label = ['', 'reminder (50% of SLA)', 'escalated (SLA passed)', 'flagged on the governance dashboard (200% of SLA)'][level];
      ledger.append({ kind: 'decision', agent_id: req.agent_id, data: { event: 'approval.escalation', approval_id: req.id, level, label } });
      if (level === 1) for (const s of req.slots) if (!s.owner_only) notifyRoles(s.roles, 'reminder', `Reminder: ${req.title}`, `/approvals?id=${req.id}`);
      if (level >= 2) notifyRoles(['governance_board'], 'escalation', `Escalated: ${req.title}`, `/approvals?id=${req.id}`);
    }
  }
}

export const hitlGrant = (sessionId: string, agentId: string, actionKey: string) =>
  db.prepare('SELECT request_id FROM hitl_grant WHERE session_id = ? AND agent_id = ? AND action_key = ? AND expires_at > ?').get(sessionId, agentId, actionKey, nowIso()) as { request_id: string } | undefined;
