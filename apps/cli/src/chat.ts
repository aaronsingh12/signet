import { createInterface } from 'node:readline/promises';
import { automationToken, env, request } from '@signet/core';

// Talk to the cloud LLM as one of your sealed agents, through the gateway, with your own prompts:
//   npm run chat -- <agent-handle>
// Acts as a deployment pipeline would: the automation client gets a one-time bootstrap credential for
// the agent and exchanges it for a workload token. Every turn is checked, ledgered and visible in the
// console. A turn that needs a person waits; approve it in the console under My Approvals.

const CONTROL = env('SIGNET_CONTROL_URL', 'http://localhost:4100');
const GATEWAY = env('SIGNET_GATEWAY_URL', 'http://localhost:8100');
const MODEL = env('SIGNET_LLM_MODEL', 'gpt-oss:120b-cloud');

async function call(method: string, url: string, token: string, body?: unknown) {
  const r = await request(url, { method, headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: body === undefined ? undefined : JSON.stringify(body), timeoutMs: 180_000 });
  const text = r.text();
  return { status: r.status, headers: r.headers, json: (text ? JSON.parse(text) : {}) as Record<string, any> };
}

async function main() {
  const handle = process.argv[2];
  if (!handle) throw new Error('usage: npm run chat -- <agent-handle>');
  const pipeline = await automationToken();
  const found = await call('GET', `${CONTROL}/api/v1/agents?q=${encodeURIComponent(handle)}`, pipeline);
  const agent = (found.json.items as { id: string; handle: string; tier: string }[] | undefined)?.find((a) => a.handle === handle);
  if (!agent) throw new Error(`no agent ${handle}; propose it in the console and take it through approval first`);
  const boot = await call('POST', `${CONTROL}/api/v1/agents/${agent.id}/bootstrap`, pipeline, { environment: 'dev' });
  if (boot.status !== 201) throw new Error(`no bootstrap credential: ${boot.json.detail ?? boot.status}`);
  const tok = await request(`${CONTROL}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bootstrap_credential: boot.json.bootstrap_credential }) });
  if (!tok.ok) throw new Error(`token exchange refused: ${tok.text()}`);
  const { token, claims } = tok.json<{ token: string; claims: { ins: string } }>();
  const session = `chat-${Date.now().toString(36)}`;
  console.log(`${handle} (${agent.tier}) · instance ${claims.ins} · session ${session} · ${MODEL} via ${GATEWAY}\nType a message; empty line or Ctrl+C to quit.\n`);
  const messages: { role: string; content: string }[] = [];
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  for (;;) {
    const text = (await rl.question('you> ')).trim();
    if (!text) break;
    messages.push({ role: 'user', content: text });
    const t0 = Date.now();
    const r = await request(`${GATEWAY}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'x-signet-session': session }, body: JSON.stringify({ model: MODEL, messages, max_tokens: 800 }), timeoutMs: 180_000 });
    const body = JSON.parse(r.text() || '{}') as Record<string, any>;
    if (r.status === 200 && !body.error) {
      const answer = String(body.choices?.[0]?.message?.content ?? '').trim();
      messages.push({ role: 'assistant', content: answer });
      console.log(`\nagent> ${answer}\n\x1b[2m[${r.headers['x-signet-decision']} · ${Date.now() - t0} ms · ${r.headers['x-signet-record-id']}]\x1b[0m\n`);
    } else {
      messages.pop();
      console.log(`\n\x1b[31m[${body.error?.decision ?? r.status}] ${body.error?.code ?? ''}: ${body.error?.message ?? JSON.stringify(body)}\x1b[0m\n`);
      if (body.error?.decision === 'kill' || body.error?.decision === 'quarantine') break;
    }
  }
  rl.close();
}

main().catch((e) => {
  console.error((e as Error).message ?? e);
  process.exit(1);
});
