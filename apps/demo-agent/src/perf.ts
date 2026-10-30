import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { REPO_ROOT } from '@signet/core';
import { MODEL, TOOLS_URL, api, deployAgent, ensureTools, gw } from './api';

// Gateway latency test (BP 2 NFR: added latency p50 <= 15 ms, p95 <= 50 ms, p99 <= 120 ms, excluding
// upstream time). Starts a separate gateway node pointed at the fast test model, with the detector
// runtime off, so the numbers are the rules path. Ledger writes are included (synchronous, RB-INV-15).

const PERF_PORT = 8102;
const PERF_GW = `http://localhost:${PERF_PORT}`;
const N_CHAT = Number(process.env.PERF_CHAT ?? 1500);
const N_TOOL = Number(process.env.PERF_TOOL ?? 1000);
const CONCURRENCY = Number(process.env.PERF_CONCURRENCY ?? 16);

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((s.length * p) / 100))]!;
};

async function run(n: number, fn: () => Promise<{ status: number; gatewayMs: number | null; ms: number }>) {
  const gwMs: number[] = [];
  const total: number[] = [];
  let errors = 0;
  let next = 0;
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      while (next < n) {
        next++;
        const r = await fn();
        if (r.status !== 200) errors++;
        if (r.gatewayMs !== null) gwMs.push(r.gatewayMs);
        total.push(r.ms);
      }
    }),
  );
  const secs = (performance.now() - t0) / 1000;
  return { gwMs, total, errors, rps: n / secs };
}

const line = (name: string, r: Awaited<ReturnType<typeof run>>) =>
  console.log(
    `${name.padEnd(28)} gateway p50 ${pct(r.gwMs, 50)} · p95 ${pct(r.gwMs, 95)} · p99 ${pct(r.gwMs, 99)} ms   ` +
      `client p95 ${pct(r.total, 95)} ms (incl. ledger write + test upstream)   ${r.rps.toFixed(0)} req/s   errors ${r.errors}`,
  );

async function main() {
  const node = spawn(process.execPath, ['--import', 'tsx', join(REPO_ROOT, 'apps/gateway/src/index.ts')], {
    env: { ...process.env, SIGNET_GATEWAY_PORT: String(PERF_PORT), SIGNET_NODE_ID: 'gw-perf', SIGNET_LLM_BASE_URL: `${TOOLS_URL}/llm/v1`, SIGNET_DET_RUNTIME: 'off' },
    stdio: ['ignore', 'pipe', 'inherit'],
    cwd: join(REPO_ROOT, 'apps/gateway'),
  });
  await new Promise<void>((resolve, reject) => {
    node.stdout!.on('data', (d: Buffer) => d.toString().includes('enforcing on') && resolve());
    node.on('exit', () => reject(new Error('perf gateway exited')));
  });
  try {
    await ensureTools();
    const reg = await api('owner', 'POST', '/agents', { handle: `perf-agent-${Date.now().toString(36)}`, name: 'Perf agent', purpose: 'Latency test', sponsor: 'ravi.kapoor@northwind.example', tier: 'T4', autonomy_level: 'L2' });
    const seal = await api('security', 'POST', `/agents/${reg.json.id}/certificates`, {
      models: [{ model: MODEL, region: 'unverified' }],
      tools: [{ server: 'mcp://orders', data_scopes: ['personal'], actions: [{ name: 'lookup_order', impact: 'read', constraints: { order_id: { pattern: '^A-[0-9]{4}$' } } }] }],
      data_classes: { prompt: ['personal'], forbidden: ['payment_card'] },
      limits: { rpm: 1_000_000, tokens_per_day: 1_000_000_000, usd_per_day: 0, tool_calls_per_session: 1_000_000 },
      environments: ['dev'],
    });
    if (seal.status !== 201) throw new Error(JSON.stringify(seal.json));
    const tok = await deployAgent(reg.json.id);
    await new Promise((r) => setTimeout(r, 500));
    const token = tok.token as string;
    const prompt = { model: MODEL, messages: [{ role: 'system', content: 'You are a support assistant.' }, { role: 'user', content: 'Where is order A-1182 for maria.lopez@mail.example? It was due on Tuesday.' }] };
    console.log(`gateway latency test · ${CONCURRENCY} concurrent clients · node gw-perf (test upstream, detectors off)\n`);
    line(`llm_call ×${N_CHAT} (DLP tokenise)`, await run(N_CHAT, () => gw(PERF_GW, '/v1/chat/completions', token, prompt)));
    let id = 0;
    line(`tool_call ×${N_TOOL} (MCP)`, await run(N_TOOL, () => gw(PERF_GW, '/v1/mcp/orders', token, { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name: 'lookup_order', arguments: { order_id: 'A-1182' } } })));
    console.log('\nBudget (BP 2): p50 <= 15 ms, p95 <= 50 ms, p99 <= 120 ms per request, excluding upstream time.');
  } finally {
    node.kill();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
