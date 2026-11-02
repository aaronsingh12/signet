import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO_ROOT, env } from '@signet/core';

// An isolated Signet stack for one e2e suite: its own data directory (fresh database, keys, ledger),
// its own ports, and the fixture tools. Nothing it does reaches the developer's real database. The
// identity provider (Keycloak) and the cloud LLM are the real ones from .env; a suite that needs them
// fails if they are not there rather than pretending.

export const PORTS = { control: 4910, gw1: 8910, gw2: 8911, fixtures: 7910 };

export interface Stack {
  dataDir: string;
  env: Record<string, string>;
  stop(keepData?: boolean): Promise<void>;
}

async function waitFor(url: string, what: string, ms = 90_000) {
  const until = Date.now() + ms;
  let last = '';
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
      last = `status ${r.status}`;
    } catch (e) {
      last = (e as Error).message;
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`${what} did not come up at ${url} (${last})`);
}

export async function requireIdentityProvider() {
  const issuer = env('SIGNET_OIDC_ISSUER', 'http://localhost:8180/realms/signet');
  try {
    const r = await fetch(`${issuer}/.well-known/openid-configuration`);
    if (!r.ok) throw new Error(`status ${r.status}`);
  } catch (e) {
    throw new Error(`the identity provider at ${issuer} is not reachable (${(e as Error).message}); start it with "npm run up"`);
  }
}

export async function startStack(label: string): Promise<Stack> {
  await requireIdentityProvider();
  const dataDir = mkdtempSync(join(tmpdir(), `signet-e2e-${label}-`));
  const stackEnv: Record<string, string> = {
    SIGNET_DATA_DIR: dataDir,
    SIGNET_CONTROL_PORT: String(PORTS.control),
    SIGNET_CONTROL_URL: `http://localhost:${PORTS.control}`,
    SIGNET_GATEWAY_URL: `http://localhost:${PORTS.gw1}`,
    SIGNET_GATEWAY2_URL: `http://localhost:${PORTS.gw2}`,
    SIGNET_FIXTURES_PORT: String(PORTS.fixtures),
    SIGNET_FIXTURES_URL: `http://localhost:${PORTS.fixtures}`,
    // The fixture tools run on localhost, which tool calls may only reach when this is set.
    SIGNET_TOOL_PRIVATE_DESTINATIONS: 'allow',
    SIGNET_FIXTURE_TOOL_KEY: randomBytes(24).toString('base64url'),
    SIGNET_FIXTURE_SN_SECRET: randomBytes(24).toString('base64url'),
  };
  const children: ChildProcess[] = [];
  const logs: string[] = [];
  const start = (name: string, entry: string, cwd: string, extra: Record<string, string> = {}) => {
    const c = spawn(process.execPath, ['--import', 'tsx', entry], { cwd, env: { ...process.env, ...stackEnv, ...extra }, stdio: ['ignore', 'pipe', 'pipe'] });
    const keep = (d: Buffer) => {
      for (const l of d.toString().split(/\r?\n/)) if (l.trim()) logs.push(`[${name}] ${l}`);
      if (logs.length > 400) logs.splice(0, logs.length - 400);
    };
    c.stdout!.on('data', keep);
    c.stderr!.on('data', keep);
    children.push(c);
    return c;
  };
  const stop = async (keepData = false) => {
    for (const c of children) c.kill();
    await new Promise((r) => setTimeout(r, 500));
    if (!keepData) rmSync(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  };
  try {
    start('fixtures', join(REPO_ROOT, 'apps/e2e/src/fixtures.ts'), join(REPO_ROOT, 'apps/e2e'));
    start('control', join(REPO_ROOT, 'apps/control/src/index.ts'), join(REPO_ROOT, 'apps/control'));
    await waitFor(`http://localhost:${PORTS.control}/healthz`, 'control plane');
    start('gw-1', join(REPO_ROOT, 'apps/gateway/src/index.ts'), join(REPO_ROOT, 'apps/gateway'), { SIGNET_GATEWAY_PORT: String(PORTS.gw1), SIGNET_NODE_ID: 'e2e-a1' });
    start('gw-2', join(REPO_ROOT, 'apps/gateway/src/index.ts'), join(REPO_ROOT, 'apps/gateway'), { SIGNET_GATEWAY_PORT: String(PORTS.gw2), SIGNET_NODE_ID: 'e2e-a2' });
    await Promise.all([
      waitFor(`http://localhost:${PORTS.gw1}/healthz`, 'gateway e2e-a1'),
      waitFor(`http://localhost:${PORTS.gw2}/healthz`, 'gateway e2e-a2'),
      waitFor(`http://localhost:${PORTS.fixtures}/crm/customers/x`, 'fixture tools'),
    ]);
    // The injection detector loads its model in the background. Suites start once every node reports
    // it ready (or definitively absent), so a verdict is never missing just because the stack is young.
    for (const port of [PORTS.gw1, PORTS.gw2]) {
      const until = Date.now() + 180_000;
      for (;;) {
        const h = (await (await fetch(`http://localhost:${port}/healthz`)).json()) as { detectors: { runtime: string } };
        if (h.detectors.runtime !== 'not loaded') break;
        if (Date.now() > until) throw new Error(`detector runtime on :${port} did not load within 180 s`);
        await new Promise((r) => setTimeout(r, 500));
      }
    }
  } catch (e) {
    console.error(logs.slice(-40).join('\n'));
    await stop(true);
    throw e;
  }
  for (const [k, v] of Object.entries(stackEnv)) process.env[k] = v;
  return { dataDir, env: stackEnv, stop: async (keep) => {
    if (keep) console.error(`\n--- last stack output (data kept in ${dataDir}) ---\n${logs.slice(-60).join('\n')}`);
    await stop(keep);
  } };
}
