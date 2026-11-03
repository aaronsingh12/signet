import { GW_A1, MODEL, TOOLS_URL, api, approveAll, deployAgent, ensureTools, gw, mcp, onboard, type GwResult, type Json, check, outcome } from './api';

// Phase 2 gate (BP 20.3) as an e2e suite: a T2 agent through the 8-stage lifecycle and the approval
// matrix, shadow -> canary -> enforce, runtime human approval (sync, async, session grant, reject), and
// the ServiceNow connector against the fixture stand-in. Every step checks its outcome.

const line = (s = '') => console.log(s);
let n = 0;
const head = (s: string) => line(`\n\x1b[1m${++n}. ${s}\x1b[0m`);
const say = (s: string) => line(`   ${s}`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function show(r: GwResult, want?: string | string[]) {
  const got = outcome(r);
  if (want) check((Array.isArray(want) ? want : [want]).includes(got), `expected ${want}, got ${got}: ${JSON.stringify(r.json).slice(0, 300)}`);
  const rpc = r.json.jsonrpc ? r.json : null;
  const err = rpc?.error?.data ?? r.json.error;
  if (r.status === 200 && !err) {
    const out = rpc ? JSON.stringify(rpc.result?.structuredContent ?? rpc.result ?? rpc) : String(r.json.choices?.[0]?.message?.content ?? JSON.stringify(r.json)).trim();
    say(`\x1b[32m${r.decision ?? 'allow'}\x1b[0m  ${r.ms} ms  ${r.record ?? ''}`);
    say(`→ ${out.replace(/\s+/g, ' ').slice(0, 160)}`);
  } else {
    say(`\x1b[31m${err?.decision ?? r.status}\x1b[0m  ${r.status} ${err?.code ?? ''}  rules=${(err?.rule_ids ?? []).join(',')}`);
    say(`→ ${err?.message ?? JSON.stringify(r.json).slice(0, 200)}`);
  }
  return err as Json | undefined;
}

const chat = (content: string) => ({ model: MODEL, messages: [{ role: 'user', content }], max_tokens: 200 });

// The approvers' side of a runtime approval: Jonas finds it in "My approvals" and decides; for an
// approval, every approver group on it signs (Priya takes the owner-approvers slot).
async function decideRuntime(match: (a: Json) => boolean, decision: string, comment?: string) {
  for (let i = 0; i < 40; i++) {
    const mine = await api('security', 'GET', '/approvals?mine=1');
    const a = (mine.json.items as Json[]).find((x) => x.type === 'runtime_hitl' && x.status === 'pending' && match(x));
    if (a) {
      const slots = decision === 'approve' ? (a.slots as Json[]) : [a.slots[0]];
      for (const s of slots) {
        const who = s.owner_allowed ? 'owner' : 'security';
        const d = await api(who, 'POST', `/approvals/${a.id}/decisions`, { decision, slot: s.slot, comment });
        say(`${who === 'owner' ? 'Priya' : 'Jonas'} (${s.slot}) decides ${decision} → ${d.status} ${d.json.status ?? d.json.detail}`);
      }
      return a.id as string;
    }
    await sleep(250);
  }
  throw new Error('runtime approval did not appear');
}

export async function run() {
  line(`Signet Phase 2 gate demo · cloud LLM ${MODEL}`);
  await ensureTools();

  head('Platform admin connects ServiceNow (OAuth client credentials; the secret goes to the broker)');
  const existing = (await api('platform', 'GET', '/connectors')).json.items as Json[];
  let conn = existing.find((c) => c.config.instance_url === `${TOOLS_URL}/servicenow`);
  if (!conn) {
    const c = await api('platform', 'POST', '/connectors', { name: 'Northwind ServiceNow (stand-in)', instance_url: `${TOOLS_URL}/servicenow`, auth: 'oauth_client_credentials', client_id: 'signet', secret: process.env.SIGNET_FIXTURE_SN_SECRET! });
    conn = c.json;
    say(`${c.status} ${conn.id} ${conn.config?.instance_url}`);
  }
  const t = await api('platform', 'POST', `/connectors/${conn.id}/test`);
  say(`self-test ${t.json.ok ? 'passed' : 'FAILED'}: ${(t.json.checks as Json[]).map((c) => `${c.check}=${c.ok ? 'ok' : 'no'}`).join(' ')}`);
  const pull = await api('platform', 'POST', `/connectors/${conn.id}/pull`);
  say(`control library pulled: ${pull.json.authority_documents} new authority documents, ${pull.json.citations} new citations (since the last pull)`);

  head('Templates the owner can start from');
  const tpls = await api('owner', 'GET', '/templates');
  say((tpls.json.items as Json[]).map((x) => `${x.id} (${x.name})`).join(' · '));

  head('Priya proposes a customer-facing refund agent from TPL-CS; Signet classifies it, Risk confirms');
  const handle = `refund-desk-${Date.now().toString(36)}`;
  const manifest = {
    models: [{ model: MODEL, region: 'unverified', max_tokens: 600 }],
    tools: [{ server: 'mcp://orders', data_scopes: ['personal'], actions: [
      { name: 'lookup_order', impact: 'read', constraints: { order_id: { pattern: '^A-[0-9]{4}$' } } },
      { name: 'issue_refund', impact: 'privileged', value_arg: 'amount', value_threshold_usd: 100, constraints: { amount: { min: 1, max: 5000 } } },
    ] }],
    data_classes: { prompt: ['personal'], forbidden: ['payment_card', 'special_category'] },
    hitl: [{ action: 'mcp://orders.issue_refund', arg: 'amount', gt: 500, approver_group: 'ops-supervisors' }],
    limits: { rpm: 120, tokens_per_day: 500_000, usd_per_day: 50, tool_calls_per_session: 40 },
    environments: ['dev'],
    tags: ['customer-facing'],
  };
  const { agentId, lifecycleId, tier } = await onboard({
    handle, name: 'Refund Desk', purpose: 'Answers customers about their orders and issues refunds',
    team: [{ user: 'arjun.mehta@northwind.example', role: 'builder' }],
    intake: { template: 'TPL-CS', users_affected: ['customers'], data_touched: ['personal'], reversibility: 'partly', planned_tools: ['lookup_order (read)', 'issue_refund (privileged)'], business_value: 'Refunds in minutes, not days' },
    manifest,
    deployTo: 'shadow',
    hooks: {
      approval: async (id) => {
        const a = (await api('owner', 'GET', `/approvals/${id}`)).json;
        say(`approval ${id}: ${(a.slots as Json[]).map((s) => s.label).join(' + ')} · pack ${String(a.pack_hash).slice(0, 12)}…`);
      },
    },
  }, say);
  let v = (await api('owner', 'GET', `/lifecycles/${lifecycleId}`)).json;
  say(`${tier} · assessments ${(v.assessments as Json[]).map((a) => `${a.type}:${a.status}`).join(', ')}`);
  say(`tests: ${(v.tests[0].suites.suites as Json[]).filter((s) => s.required).map((s) => `${s.suite}${s.passed ? '✓' : '✗'}`).join(' ')}`);
  say(`approvals: ${(v.approval.decisions as Json[]).map((d) => `${d.slot}=${d.approver}`).join(', ')} → seal ${v.lifecycle.data.cert_id}`);
  say(`deploy: ${v.deploy.mode}, ${v.deploy.shadow_days} shadow days then ${v.deploy.canary ? `${v.deploy.canary_pct}% canary` : 'enforce'}`);

  const tok = await deployAgent(agentId);
  const token = tok.token as string;
  await sleep(400);

  head('Shadow: an out-of-manifest call is recorded as would_block, not blocked');
  await mcp(GW_A1, 'orders', token, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'demo', version: '1' } }, 'shadow-1');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'delete_customer', arguments: { customer_id: 'C-1' } }, 'shadow-1'), 'would_block');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 900 } }, 'shadow-1'), 'would_block');
  v = (await api('owner', 'GET', `/lifecycles/${lifecycleId}`)).json;
  say(`shadow stats: ${JSON.stringify(v.deploy.stats)}`);

  head('Moving to enforce early is refused: T2 runs a canary first');
  const early = await api('owner', 'POST', `/lifecycles/${lifecycleId}/deploy`, { to: 'enforce' });
  say(`${early.status} ${early.json.rule}: ${early.json.detail}`);
  check(early.status === 409, 'T2 cannot skip the canary');
  const tooSoon = await api('owner', 'POST', `/lifecycles/${lifecycleId}/deploy`, { to: 'canary' });
  say(`${tooSoon.status} ${tooSoon.json.rule}: ${tooSoon.json.detail}`);
  check(tooSoon.status === 422, 'the shadow period is enforced without an override');
  for (const to of ['canary', 'enforce']) {
    const r = await api('owner', 'POST', `/lifecycles/${lifecycleId}/deploy`, { to, dev_override: true, reason: 'demo: period cut short', acknowledge_would_blocks: true });
    say(`→ ${to}: ${r.status} ${r.json.detail ?? 'ok'}`);
  }
  await sleep(400);

  head('Enforce: the same out-of-manifest call is now blocked');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'delete_customer', arguments: { customer_id: 'C-2' } }, 'enforce-1'), 'deny');

  head('Refund of USD 900 > 500: the call waits; Jonas (ops-supervisors) and Priya (owner-approvers, RB-PRIV-04) approve');
  const big = { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 900 } };
  const [held] = await Promise.all([
    mcp(GW_A1, 'orders', token, 'tools/call', big, 'enforce-1'),
    decideRuntime((a) => a.title.includes(handle), 'approve', 'customer verified'),
  ]);
  show(held, 'allow');

  head('Second refund in the same session: Jonas rejects; the agent gets approval_rejected');
  const [rej] = await Promise.all([
    mcp(GW_A1, 'orders', token, 'tools/call', { ...big, arguments: { order_id: 'A-1183', amount: 1200 } }, 'enforce-1'),
    decideRuntime((a) => a.title.includes(handle), 'reject', 'duplicate refund'),
  ]);
  show(rej, 'deny');

  head(`Model call: ${tier} without active DET-JB/DET-PII holds every allow for a person (RB-INV-06); async mode`);
  const c1 = await gw(GW_A1, '/v1/chat/completions', token, chat('In one sentence, how do refunds work?'), { 'x-signet-session': 'chat-1', 'x-signet-hitl': 'async' });
  const p1 = show(c1, 'require_approval');
  check(!!p1?.approval_id, 'the async hold returned an approval id');
  if (p1?.approval_id) {
    const d = await api('owner', 'POST', `/approvals/${p1.approval_id}/decisions`, { decision: 'approve_session', comment: 'ok for this conversation' });
    say(`Priya approves for the session → ${d.status} ${d.json.status ?? d.json.detail}`);
    head('Resubmit with the approval; the next call in the session uses the session grant');
    const first = await gw(GW_A1, '/v1/chat/completions', token, chat('In one sentence, how do refunds work?'), { 'x-signet-session': 'chat-1', 'x-signet-approval': p1.approval_id });
    show(first, 'allow');
    const history = [{ role: 'user', content: 'In one sentence, how do refunds work?' }, { role: 'assistant', content: String(first.json.choices?.[0]?.message?.content ?? '') }, { role: 'user', content: 'And in one sentence, how long do they take?' }];
    show(await gw(GW_A1, '/v1/chat/completions', token, { model: MODEL, messages: history, max_tokens: 200 }, { 'x-signet-session': 'chat-1' }), 'allow');
  }

  head('A suspicious refund: Jonas rejects it and quarantines the agent; ServiceNow gets an incident');
  const [q] = await Promise.all([
    mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1999', amount: 4900 } }, 'enforce-2'),
    decideRuntime((a) => a.title.includes(handle), 'reject_quarantine', 'refund pattern looks like fraud; investigating'),
  ]);
  show(q, 'quarantine');

  head('Release needs Owner + Security (BP 7.2)');
  const rel = await api('security', 'POST', `/agents/${agentId}/ladder`, { action: 'release', reason: 'Fraud check done; customer refund was legitimate (INC follow-up closed)' });
  say(`${rel.status} release request ${rel.json.id ?? rel.json.detail}`);
  if (rel.json.id) await approveAll(rel.json.id, 'investigation closed');
  const after = await api('security', 'GET', `/agents/${agentId}`);
  say(`agent level → ${after.json.enforcement?.level}`);

  head('Continuous control evaluation and framework scores');
  const ev = await api('risk', 'POST', '/library/evaluate');
  const counts: Record<string, number> = {};
  for (const r of ev.json.results as Json[]) counts[r.status] = (counts[r.status] ?? 0) + 1;
  say(`controls: ${Object.entries(counts).map(([k, x]) => `${k} ${x}`).join(' · ')}`);
  for (const f of (await api('risk', 'GET', '/compliance/scores')).json.items as Json[]) say(`${f.name.padEnd(28)} ${f.score ?? '-'}%`);

  head('ServiceNow: the outbox delivered risk, CI, test, indicator and incident records');
  await sleep(4000);
  const ob = await api('platform', 'GET', `/connectors/${conn.id}/outbox`);
  const byStatus: Record<string, number> = {};
  for (const e of ob.json.items as Json[]) byStatus[`${e.event}:${e.status}`] = (byStatus[`${e.event}:${e.status}`] ?? 0) + 1;
  say(Object.entries(byStatus).map(([k, x]) => `${k} ×${x}`).join(' · '));
  const dump = (await fetch(`${TOOLS_URL}/servicenow/_dump`).then((r) => r.json())) as Record<string, Json[]>;
  say(Object.entries(dump).map(([k, rows]) => `${k} ${rows.length}`).join(' · '));

  head("Priya's notifications");
  const notes = await api('owner', 'GET', '/notifications');
  for (const x of (notes.json.items as Json[]).slice(0, 6)) say(`• ${x.title}`);

  head('Annual attestation by the owner');
  const att = await api('owner', 'POST', `/agents/${agentId}/attest`, { purpose_unchanged: true, manifest_minimal: true, owner_accountable: true, note: 'controls reviewed' });
  say(`${att.status} ${att.json.detail ?? `${att.json.attestation_id} · sha256 ${String(att.json.content_sha256).slice(0, 12)}… · ${att.json.renewed_cert_id ? `seal renewed ${att.json.renewed_cert_id}` : 'seal not yet due for renewal'}`}`);
}

