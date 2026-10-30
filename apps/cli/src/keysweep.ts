import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { automationToken, env, scan, sha256 } from '@signet/core';

// Key Sweep (BP 1B.3, E32): finds model-provider and tool credentials in code, CI files and env
// files, so they can be moved behind the Secrets Broker. Only a fingerprint (SHA-256 prefix) and a
// masked preview leave this machine, never the key.
// Usage: npm run keysweep -- <dir> [--upload]

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'data', 'exports', 'models', 'tools']);
const MAX_BYTES = 1_000_000;

interface Finding {
  type: 'unmanaged_key';
  summary: string;
  location: string;
  fingerprint: string;
}

function* files(dir: string): Generator<string> {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* files(join(dir, e.name));
    } else if (e.isFile()) yield join(dir, e.name);
  }
}

const mask = (v: string) => (v.length > 12 ? `${v.slice(0, 6)}…${v.slice(-4)}` : '••••');

function sweep(root: string): Finding[] {
  const out: Finding[] = [];
  for (const f of files(root)) {
    if (statSync(f).size > MAX_BYTES) continue;
    const buf = readFileSync(f);
    if (buf.includes(0)) continue; // binary
    const lines = buf.toString('utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      for (const hit of scan(line)) {
        if (hit.tag !== 'secrets' || hit.recogniser === 'password_assignment') continue;
        out.push({ type: 'unmanaged_key', summary: `${hit.recogniser} ${mask(hit.value)}`, location: `${relative(root, f).replace(/\\/g, '/')}:${i + 1}`, fingerprint: sha256(hit.value).slice(0, 16) });
      }
    });
  }
  return out;
}

async function main() {
  const dir = resolve(process.cwd(), process.argv[2] ?? '.');
  const found = sweep(dir);
  console.log(`Key Sweep of ${dir}: ${found.length} credential(s) found`);
  for (const f of found) console.log(`  ${f.summary.padEnd(32)} ${f.location}  fp ${f.fingerprint}`);
  if (process.argv.includes('--upload') && found.length) {
    const r = await fetch(`${env('SIGNET_CONTROL_URL', 'http://localhost:4100')}/api/v1/discovery/findings`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${await automationToken()}` },
      body: JSON.stringify({ source: `keysweep:${dir.split(/[\\/]/).pop()}`, items: found }),
    });
    console.log(`uploaded to the Discovery Inbox: ${r.status} ${await r.text()}`);
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
