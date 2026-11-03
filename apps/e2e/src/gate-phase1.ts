import { CONTROL, GW_A1, GW_A2, MODEL, api, approveAll, check, deployAgent, ensureTools, gw, mcp, onboard, outcome, type GwResult, type Json } from './api';

// Phase 1 gate (BP 20.2) as an e2e suite: register agent, approve, call the real model and the fixture
// tools, DLP masking, out-of-manifest block, kill on every gateway node, ledger chain. Runs against the
// isolated stack the harness starts; every step checks its outcome and the suite fails on a mismatch.

const line = (s = '') => console.log(s);
let n = 0;
const head = (s: string) => line(`\n\x1b[1m${++n}. ${s}\x1b[0m`);
const say = (s: string) => line(`   ${s}`);

function show(r: GwResult, want?: string | string[]) {
  const got = outcome(r);
  if (want) check((Array.isArray(want) ? want : [want]).includes(got), `expected ${want}, got ${got}: ${JSON.stringify(r.json).slice(0, 300)}`);
  const rpc = r.json.jsonrpc ? r.json : null;
  const err = rpc?.error?.data ?? r.json.error;
  if (r.status === 200 && !err) {
    const out = rpc ? JSON.stringify(rpc.result?.structuredContent ?? rpc.result ?? rpc) : String(r.json.choices?.[0]?.message?.content ?? JSON.stringify(r.json)).trim();
    say(`\x1b[32m${r.decision ?? 'allow'}\x1b[0m  ${r.ms} ms (gateway ${r.gatewayMs ?? '-'} ms)  ${r.record ?? ''}`);
    say(`→ ${out.replace(/\s+/g, ' ').slice(0, 200)}`);
  } else {
    say(`\x1b[31m${err?.decision ?? r.status}\x1b[0m  ${err?.code ?? ''}  rules=${(err?.rule_ids ?? []).join(',')}  ${err?.record_id ?? ''}`);
    say(`→ ${err?.message ?? JSON.stringify(r.json).slice(0, 200)}`);
  }
}

const chat = (content: string, model = MODEL) => ({ model, messages: [{ role: 'user', content }], max_tokens: 300 });

export async function run() {
  const h1 = (await fetch(`${GW_A1}/healthz`).then((r) => r.json()).catch(() => null)) as Json | null;
  const h2 = (await fetch(`${GW_A2}/healthz`).then((r) => r.json()).catch(() => null)) as Json | null;
  if (!h1) throw new Error(`gateway not reachable at ${GW_A1}; run "npm run up" and "npm run dev:api" first`);
  line(`Signet Phase 1 gate demo · control ${CONTROL} · gateways ${h1.node}${h2 ? `, ${h2.node}` : ''} · cloud LLM ${h1.cloud_llm.join(', ')}`);
  line(`policy engine: ${h1.policy_engine} · DET-INJ runtime: ${h1.detectors.runtime}`);

  head('Platform admin puts the tool credential in the Secrets Broker and registers tool aliases');
  await ensureTools();
  const tools = await api('platform', 'GET', '/tools');
  say(`tools: ${tools.json.items.map((t: Json) => `${t.kind}://${t.alias}`).join(', ')} · credential held only by the broker`);

  head('Priya (owner) proposes an internal support agent; Signet classifies it from the intake');
  const handle = `refund-concierge-${Date.now().toString(36)}`;

  const seal = {
    models: [{ model: MODEL, region: 'unverified', max_tokens: 800 }],
    tools: [
      {
        server: 'mcp://orders',
        data_scopes: ['personal'],
        actions: [
          { name: 'lookup_order', impact: 'read', constraints: { order_id: { pattern: '^A-[0-9]{4}$' } } },
          { name: 'get_document', impact: 'read' },
          { name: 'create_ticket', impact: 'write', constraints: { priority: { enum: ['low', 'normal', 'high'] } } },
          { name: 'issue_refund', impact: 'privileged', value_arg: 'amount', value_threshold_usd: 100, constraints: { amount: { min: 1, max: 5000 } } },
        ],
      },
      { server: 'http://crm', data_scopes: ['personal'], actions: [{ name: 'get_customer', impact: 'read' }, { name: 'add_note', impact: 'write' }] },
    ],
    data_classes: { prompt: ['personal'], forbidden: ['payment_card', 'special_category'] },
    hitl: [{ action: 'mcp://orders.issue_refund', arg: 'amount', gt: 2000, approver_group: 'ops-supervisors' }],
    limits: { rpm: 120, tokens_per_day: 500_000, usd_per_day: 50, tool_calls_per_session: 40 },
    environments: ['dev'],
    tags: ['customer-facing'],
  };

  const { agentId, tier } = await onboard({
    handle,
    name: 'Refund Concierge',
    purpose: 'Helps support staff answer order questions and issue small refunds',
    team: [{ user: 'arjun.mehta@northwind.example', role: 'builder' }, { user: 'ananya.rao@northwind.example', role: 'operator' }],
    intake: { users_affected: ['internal'], data_touched: ['personal'], reversibility: 'yes', planned_tools: ['orders lookup (read)', 'support tickets (write)', 'crm notes (write)'], business_value: 'Shorter support queues' },
    manifest: seal,
    hooks: {
      drafted: async (lc) => {
        head('Priya drafts a manifest naming another provider');
        const wrong = await api('owner', 'PUT', `/lifecycles/${lc}/manifest`, { ...seal, models: [{ model: 'gpt-4o', region: 'us' }] });
        say(`${wrong.status} ${wrong.json.rule}: ${wrong.json.detail}`);
        check(wrong.status === 422 && wrong.json.rule === 'RB-INV-19', 'a second provider is refused (RB-INV-19)');
      },
      approval: async (id) => {
        head('Assessments and baseline tests pass; the approval matrix asks for Owner + Security');
        head('Priya tries to take the Security slot on her own agent');
        const self = await api('owner', 'POST', `/approvals/${id}/decisions`, { decision: 'approve', slot: 'security' });
        say(`${self.status} ${self.json.rule}: ${self.json.detail}`);
        check(self.status === 403, 'owner cannot take the Security slot');
        head("Ananya (Risk) is on this agent's build team, so she cannot approve it");
        const sod = await api('risk', 'POST', `/approvals/${id}/decisions`, { decision: 'approve' });
        say(`${sod.status} ${sod.json.rule}: ${sod.json.detail}`);
        check(sod.status === 403 && sod.json.rule === 'RB-INV-09', 'build team cannot approve (RB-INV-09)');
        head('Priya (Owner slot) and Jonas (Security slot) approve; Signet compiles the policy and signs the seal');
      },
    },
  }, say);
  const agent = await api('security', 'GET', `/agents/${agentId}`);
  const cert = agent.json.certificate ?? {};
  say(`${tier} ${agentId} · ${cert.cert_id} ${cert.version} · policy sha256 ${String(cert.policy_sha256).slice(0, 16)}… · valid to ${String(cert.valid_to).slice(0, 10)} · rollout enforce`);

  head('Deploy: the pipeline gets a one-time bootstrap credential; the agent exchanges it for a workload token');
  const tok = await deployAgent(agentId);
  const token = tok.token as string;
  say(`instance ${tok.claims.ins} · ${tok.claims.sub} · expires in ${tok.expires_in} s`);
  await new Promise((r) => setTimeout(r, 400)); // seal push reaches both gateway nodes

  head('Model call to gpt-oss through gateway gw-a1');
  show(await gw(GW_A1, '/v1/chat/completions', token, chat('In one sentence: what should a customer do if an order arrives damaged?')), 'allow');

  head('Personal data is tokenised before the model sees it and restored in the answer');
  show(await gw(GW_A1, '/v1/chat/completions', token, chat('Repeat back exactly, nothing else: "Contact maria.lopez@mail.example about order A-1182".')), 'allow_with_obligations');

  head('MCP: the agent sees only the tools in its seal (delete_customer is filtered out)');
  await mcp(GW_A1, 'orders', token, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'demo', version: '1' } });
  const list = await mcp(GW_A1, 'orders', token, 'tools/list');
  say(`tools/list → ${list.json.result.tools.map((t: Json) => t.name).join(', ')}`);

  head('Tool call: lookup_order (credential injected by the gateway; the agent never held it)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'lookup_order', arguments: { order_id: 'A-1182' } }), 'allow');

  head('Tool call with an argument outside the seal constraint (order_id pattern)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'lookup_order', arguments: { order_id: "A-1182' OR 1=1" } }), 'deny');

  head('HTTP tool proxy: crm.get_customer');
  show(await gw(GW_A1, '/v1/tools/http/crm/get_customer', token, { id: 'C-7781' }), 'allow');

  head('Privileged refund of USD 50 (T3: runs without approval)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 50 } }), 'allow');

  head('Refund of USD 3,200 hits the seal HITL rule (> 2,000 → ops-supervisors); the agent asks for an async answer');
  const big = { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 3200 } };
  const parked = await mcp(GW_A1, 'orders', token, 'tools/call', big, 'demo-session', { 'x-signet-hitl': 'async' });
  show(parked, 'require_approval');
  const approvalId = (parked.json.error?.data ?? parked.json.error)?.approval_id as string | undefined;
  check(!!approvalId, 'the parked refund returned an approval id');
  if (approvalId) {
    const d = await api('security', 'POST', `/approvals/${approvalId}/decisions`, { decision: 'approve', comment: 'customer verified by phone' });
    say(`Jonas (ops-supervisors) → ${d.status} ${d.json.status ?? d.json.detail}`);
    head('The agent resubmits the same call with the single-use approval');
    show(await mcp(GW_A1, 'orders', token, 'tools/call', big, 'demo-session', { 'x-signet-approval': approvalId }), 'allow');
    head('Reusing the approval is refused');
    show(await mcp(GW_A1, 'orders', token, 'tools/call', big, 'demo-session', { 'x-signet-approval': approvalId }), 'deny');
  }

  head('Indirect injection: the agent reads a poisoned document (DET-INJ in shadow scores it, nothing enforced)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'get_document', arguments: { id: 'doc_7781' } }, 'session-shadow'), 'allow');

  head('Jonas promotes DET-INJ to active (dev override of the 14-day shadow, recorded in the ledger)');
  const promote = await api('security', 'POST', '/detectors/DET-INJ/mode', { mode: 'active', reason: 'Phase 1 gate demo', dev_override: true });
  say(`${promote.status} DET-INJ → ${promote.json.mode ?? promote.json.detail}`);
  await new Promise((r) => setTimeout(r, 400));

  head('Same poisoned document with DET-INJ active: the session is tainted');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'get_document', arguments: { id: 'doc_7781' } }, 'session-hijack'));
  head('The hijacked agent then tries the refund the document asked for → Hijack rule (RB-KILL-01): T3 is quarantined');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 60 } }, 'session-hijack'), 'quarantine');

  head('Jonas investigates and asks to release the quarantine; Owner + Security approve (human-only)');
  const rel = await api('security', 'POST', `/agents/${agentId}/ladder`, { action: 'release', reason: 'Injected document removed from the store; investigation INC-1042 closed' });
  say(`${rel.status} release request ${rel.json.id ?? rel.json.detail}`);
  if (rel.json.id) await approveAll(rel.json.id, 'investigation closed');
  const lvl = await api('security', 'GET', `/agents/${agentId}`);
  say(`agent level → ${lvl.json.level ?? lvl.json.enforcement?.level ?? 'see console'}`);
  const tok2 = await deployAgent(agentId); // quarantine revoked the old tokens
  await new Promise((r) => setTimeout(r, 300));
  const t2 = tok2.token as string;
  say(`new instance ${tok2.claims.ins}`);

  head('Out-of-manifest: delete_customer is not in the seal (each attempt counts toward the RB-KILL-04 kill)');
  show(await mcp(GW_A1, 'orders', t2, 'tools/call', { name: 'delete_customer', arguments: { customer_id: 'C-1' } }), 'deny');

  head('A card number in a prompt: payment_card is forbidden → block and kill (RB-KILL-02), pushed to every gateway node');
  const killCall = await gw(GW_A1, '/v1/chat/completions', t2, chat('Refund the order paid with card 4111 1111 1111 1111 please.'));
  show(killCall, 'kill');
  await new Promise((r) => setTimeout(r, 300));
  const events = await api('security', 'GET', `/enforcement-events?agent=${agentId}`);
  const kill = events.json.items.find((e: Json) => e.level === 'killed');
  check(!!kill, 'a kill event was recorded');
  if (kill) {
    for (const a of kill.acks) say(`kill ${kill.id} acknowledged by ${a.gateway_node_id} in ${a.latency_ms} ms`);
    check(kill.acks.length === kill.nodes_expected, 'every gateway node acknowledged the kill');
    say(`${kill.acks.length}/${kill.nodes_expected} gateway nodes acknowledged · max ${Math.max(...kill.acks.map((a: Json) => a.latency_ms))} ms`);
  }

  head('The killed agent tries the other gateway node (gw-a2)');
  show(await gw(GW_A2, '/v1/chat/completions', t2, chat('Are you still there?')), 'deny');
  const again = await deployAgent(agentId).catch((e: Error) => ({ error: e.message }));
  say(`new bootstrap for the killed agent → ${'error' in again ? again.error.slice(0, 120) : 'issued (unexpected)'}`);

  head('Evidence: ledger chain, inclusion proof, offline package');
  const v = await api('security', 'POST', '/ledger/verify', {});
  check(v.json.ok === true, 'ledger chain verifies');
  say(`chain ${v.json.ok ? 'verified' : 'BROKEN'} · ${v.json.count} records · ${v.json.roots_checked} signed daily roots valid=${v.json.roots_valid} · ${v.json.ms} ms`);
  if (killCall.json.error?.record_id) {
    const proof = await api('security', 'GET', `/ledger/records/${killCall.json.error.record_id}/proof`);
    say(`record ${proof.json.record_id}: leaf ${proof.json.index} of ${proof.json.tree_size}, ${proof.json.proof.length}-step Merkle path to ${proof.json.provisional ? "today's provisional root" : 'the signed daily root'} ${String(proof.json.merkle_root).slice(0, 16)}…`);
  }
}

