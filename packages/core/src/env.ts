import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// SIGNET_HOME points bundled builds and containers at their install directory.
export const REPO_ROOT = process.env.SIGNET_HOME ?? resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

// Reads REPO_ROOT/.env into process.env without overriding values already set.
export function loadEnv(): void {
  const file = join(REPO_ROOT, '.env');
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && process.env[m[1]!] === undefined) process.env[m[1]!] = m[2]!.replace(/^["']|["']$/g, '');
  }
}

loadEnv();

export const DATA_DIR = process.env.SIGNET_DATA_DIR ?? join(REPO_ROOT, 'data');

export const env = (name: string, fallback: string) => process.env[name] ?? fallback;

// Dev-only shared secrets between control plane and gateways, generated on first use.
// Production supplies these from a secret manager.
const DEV_SECRETS = ['SIGNET_INTERNAL_TOKEN', 'SIGNET_VAULT_KEY', 'SIGNET_BROKER_KEY', 'SIGNET_DEMO_TOOL_KEY'];

// Several processes start together on a fresh install, so the file is created once, atomically,
// with every known secret in it; a process that loses the race reads the winner's file.
function readDevSecrets(file: string): Record<string, string> {
  for (let i = 0; ; i++) {
    try {
      return JSON.parse(readFileSync(file, 'utf8')) as Record<string, string>;
    } catch (e) {
      if (i >= 50) throw e; // the creator may still be writing; wait a little
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
  }
}

export function devSecret(name: string): string {
  const fromEnv = process.env[name];
  if (fromEnv) return fromEnv;
  mkdirSync(DATA_DIR, { recursive: true });
  const file = join(DATA_DIR, 'dev-secrets.json');
  if (!existsSync(file)) {
    const fresh = Object.fromEntries([...new Set([...DEV_SECRETS, name])].map((k) => [k, randomBytes(32).toString('base64url')]));
    try {
      writeFileSync(file, JSON.stringify(fresh, null, 2), { mode: 0o600, flag: 'wx' });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
  }
  const all = readDevSecrets(file);
  if (!all[name]) {
    all[name] = randomBytes(32).toString('base64url');
    writeFileSync(file, JSON.stringify(all, null, 2), { mode: 0o600 });
  }
  return all[name]!;
}
