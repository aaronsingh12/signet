import { CONTROL, GW_A1, GW_A2, MODEL, api, deployAgent, ensureTools, gw, mcp, type GwResult, type Json } from './api';

// Phase 1 gate demo (BP 20.2): register agent, approve, call model and tool, see DLP mask, trigger
// out-of-manifest block, kill in under 1 s on every gateway node, verify the ledger chain.
// Run `npm run up` and `npm run dev:api` (or `npm run dev`) first.

const line = (s = '') => console.log(s);
let n = 0;
const head = (s: string) => line(`\n\x1b[1m${++n}. ${s}\x1b[0m`);
const say = (s: string) => line(`   ${s}`);

function show(r: GwResult) {
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

async function main() {
  const h1 = (await fetch(`${GW_A1}/healthz`).then((r) => r.json()).catch(() => null)) as Json | null;
  const h2 = (await fetch(`${GW_A2}/healthz`).then((r) => r.json()).catch(() => null)) as Json | null;
  if (!h1) throw new Error(`gateway not reachable at ${GW_A1}; run "npm run up" and "npm run dev:api" first`);
  line(`Signet Phase 1 gate demo · control ${CONTROL} · gateways ${h1.node}${h2 ? `, ${h2.node}` : ''} · cloud LLM ${h1.cloud_llm.join(', ')}`);
  line(`policy engine: ${h1.policy_engine} · DET-INJ runtime: ${h1.detectors.runtime}`);

  head('Platform admin puts the tool credential in the Secrets Broker and registers tool aliases');
  await ensureTools();
  const tools = await api('platform', 'GET', '/tools');
  say(`tools: ${tools.json.items.map((t: Json) => `${t.kind}://${t.alias}`).join(', ')} · credential held only by the broker`);

  head('Priya (owner) proposes a T3 customer-service agent');
  const handle = `refund-concierge-${Date.now().toString(36)}`;
  const reg = await api('owner', 'POST', '/agents', { handle, name: 'Refund Concierge', purpose: 'Answers order questions and issues small refunds', sponsor: 'ravi.kapoor@northwind.example', tier: 'T3', autonomy_level: 'L2', team: [{ user: 'arjun.mehta@northwind.example', role: 'builder' }, { user: 'ananya.rao@northwind.example', role: 'operator' }] });
  const agentId = reg.json.id as string;
  say(`${reg.status} ${agentId} (${handle}) owner ${reg.json.owner}`);

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

  head('Priya tries to approve her own agent');
  const self = await api('owner', 'POST', `/agents/${agentId}/certificates`, seal);
  say(`${self.status} ${self.json.rule}: ${self.json.detail}`);

  head("Ananya (Risk, may approve seals) is on this agent's build team, so she cannot approve it");
  const sod = await api('risk', 'POST', `/agents/${agentId}/certificates`, seal);
  say(`${sod.status} ${sod.json.rule}: ${sod.json.detail}`);

  head('Jonas (Security) tries a seal naming another provider');
  const wrong = await api('security', 'POST', `/agents/${agentId}/certificates`, { ...seal, models: [{ model: 'gpt-4o', region: 'us' }] });
  say(`${wrong.status} ${wrong.json.rule}: ${wrong.json.detail}`);

  head('Jonas approves; Signet compiles the policy and signs the seal');
  const issued = await api('security', 'POST', `/agents/${agentId}/certificates`, seal);
  say(`${issued.status} ${issued.json.certificate?.cert_id} ${issued.json.certificate?.version} · policy sha256 ${String(issued.json.certificate?.policy_sha256).slice(0, 16)}… · valid to ${issued.json.certificate?.valid_to?.slice(0, 10)}`);

  head('Deploy: the pipeline gets a one-time bootstrap credential; the agent exchanges it for a workload token');
  const tok = await deployAgent(agentId);
  const token = tok.token as string;
  say(`instance ${tok.claims.ins} · ${tok.claims.sub} · expires in ${tok.expires_in} s`);
  await new Promise((r) => setTimeout(r, 400)); // seal push reaches both gateway nodes

  head('Model call to gpt-oss through gateway gw-a1');
  show(await gw(GW_A1, '/v1/chat/completions', token, chat('In one sentence: what should a customer do if an order arrives damaged?')));

  head('Personal data is tokenised before the model sees it and restored in the answer');
  show(await gw(GW_A1, '/v1/chat/completions', token, chat('Repeat back exactly, nothing else: "Contact maria.lopez@mail.example about order A-1182".')));

  head('MCP: the agent sees only the tools in its seal (delete_customer is filtered out)');
  await mcp(GW_A1, 'orders', token, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'demo', version: '1' } });
  const list = await mcp(GW_A1, 'orders', token, 'tools/list');
  say(`tools/list → ${list.json.result.tools.map((t: Json) => t.name).join(', ')}`);

  head('Tool call: lookup_order (credential injected by the gateway; the agent never held it)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'lookup_order', arguments: { order_id: 'A-1182' } }));

  head('Tool call with an argument outside the seal constraint (order_id pattern)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'lookup_order', arguments: { order_id: "A-1182' OR 1=1" } }));

  head('HTTP tool proxy: crm.get_customer');
  show(await gw(GW_A1, '/v1/tools/http/crm/get_customer', token, { id: 'C-7781' }));

  head('Privileged refund of USD 50 (T3: runs without approval)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 50 } }));

  head('Refund of USD 3,200 hits the seal HITL rule (> 2,000 → ops-supervisors)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 3200 } }));

  head('Indirect injection: the agent reads a poisoned document (DET-INJ in shadow scores it, nothing enforced)');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'get_document', arguments: { id: 'doc_7781' } }, 'session-shadow'));

  head('Jonas promotes DET-INJ to active (dev override of the 14-day shadow, recorded in the ledger)');
  const promote = await api('security', 'POST', '/detectors/DET-INJ/mode', { mode: 'active', reason: 'Phase 1 gate demo', dev_override: true });
  say(`${promote.status} DET-INJ → ${promote.json.mode ?? promote.json.detail}`);
  await new Promise((r) => setTimeout(r, 400));

  head('Same poisoned document with DET-INJ active: the session is tainted');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'get_document', arguments: { id: 'doc_7781' } }, 'session-hijack'));
  head('The hijacked agent then tries the refund the document asked for → Hijack rule (RB-KILL-01): T3 is quarantined');
  show(await mcp(GW_A1, 'orders', token, 'tools/call', { name: 'issue_refund', arguments: { order_id: 'A-1182', amount: 60 } }, 'session-hijack'));

  head('Jonas investigates and releases the quarantine (human-only); the agent redeploys');
  const rel = await api('security', 'POST', `/agents/${agentId}/ladder`, { action: 'release', reason: 'Injected document removed from the store; investigation INC-1042 closed' });
  say(`${rel.status} release → ${rel.json.level ?? rel.json.detail}`);
  const tok2 = await deployAgent(agentId); // quarantine revoked the old tokens
  await new Promise((r) => setTimeout(r, 300));
  const t2 = tok2.token as string;
  say(`new instance ${tok2.claims.ins}`);

  head('Out-of-manifest: delete_customer is not in the seal (each attempt counts toward the RB-KILL-04 kill)');
  show(await mcp(GW_A1, 'orders', t2, 'tools/call', { name: 'delete_customer', arguments: { customer_id: 'C-1' } }));

  head('A card number in a prompt: payment_card is forbidden → block and kill (RB-KILL-02), pushed to every gateway node');
  const killCall = await gw(GW_A1, '/v1/chat/completions', t2, chat('Refund the order paid with card 4111 1111 1111 1111 please.'));
  show(killCall);
  await new Promise((r) => setTimeout(r, 300));
  const events = await api('security', 'GET', `/enforcement-events?agent=${agentId}`);
  const kill = events.json.items.find((e: Json) => e.level === 'killed');
  if (kill) {
    for (const a of kill.acks) say(`kill ${kill.id} acknowledged by ${a.gateway_node_id} in ${a.latency_ms} ms`);
    say(`${kill.acks.length}/${kill.nodes_expected} gateway nodes acknowledged · max ${Math.max(...kill.acks.map((a: Json) => a.latency_ms))} ms`);
  }

  head('The killed agent tries the other gateway node (gw-a2)');
  show(await gw(GW_A2, '/v1/chat/completions', t2, chat('Are you still there?')));
  const again = await deployAgent(agentId).catch((e: Error) => ({ error: e.message }));
  say(`new bootstrap for the killed agent → ${'error' in again ? again.error.slice(0, 120) : 'issued (unexpected)'}`);

  head('Evidence: ledger chain, inclusion proof, offline package');
  const v = await api('security', 'POST', '/ledger/verify', {});
  say(`chain ${v.json.ok ? 'verified' : 'BROKEN'} · ${v.json.count} records · ${v.json.roots_checked} signed daily roots valid=${v.json.roots_valid} · ${v.json.ms} ms`);
  if (killCall.json.error?.record_id) {
    const proof = await api('security', 'GET', `/ledger/records/${killCall.json.error.record_id}/proof`);
    say(`record ${proof.json.record_id}: leaf ${proof.json.index} of ${proof.json.tree_size}, ${proof.json.proof.length}-step Merkle path to ${proof.json.provisional ? "today's provisional root" : 'the signed daily root'} ${String(proof.json.merkle_root).slice(0, 16)}…`);
  }
  line('\nNext: npm run verify   (exports a .sep evidence package and checks it offline)');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
