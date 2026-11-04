import { db } from './db';
import { PolicyError } from './errors';

// Counters shared by every control and gateway instance. On Vercel each container has its own
// memory and restarts cold, so rate limits, daily budgets and repeat-violation windows live here.

const minuteBucket = (now: number) => Math.floor(now / 60_000);
const day = (now: number) => new Date(now).toISOString().slice(0, 10);
const tenMinuteBucket = (now: number) => Math.floor(now / 600_000);

async function bump(key: string, expiresMs: number, tokens = 0, usd = 0): Promise<{ n: number; tokens: number; usd: number }> {
  return (await db.prepare(
    `INSERT INTO shared_counter (key, n, tokens, usd, expires_ms) VALUES (?, 1, ?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET n = shared_counter.n + 1, tokens = shared_counter.tokens + excluded.tokens, usd = shared_counter.usd + excluded.usd
     RETURNING n, tokens, usd`,
  ).get(key, tokens, usd, expiresMs)) as { n: number; tokens: number; usd: number };
}

async function read(key: string): Promise<{ n: number; tokens: number; usd: number }> {
  const row = (await db.prepare('SELECT n, tokens, usd FROM shared_counter WHERE key = ?').get(key)) as { n: number; tokens: number; usd: number } | undefined;
  return { n: Number(row?.n ?? 0), tokens: Number(row?.tokens ?? 0), usd: Number(row?.usd ?? 0) };
}

/** One request against the agent's per-minute window; returns the count so far and today's usage. */
export async function takeRequest(agentId: string): Promise<{ in_minute: number; tokens_today: number; usd_today: number }> {
  const now = Date.now();
  const minute = await bump(`rpm:${agentId}:${minuteBucket(now)}`, now + 120_000);
  const today = await read(`day:${agentId}:${day(now)}`);
  return { in_minute: minute.n, tokens_today: today.tokens, usd_today: today.usd };
}

export async function addUsage(agentId: string, tokens: number, usd: number): Promise<void> {
  const now = Date.now();
  await bump(`day:${agentId}:${day(now)}`, now + 2 * 86_400_000, Math.max(0, Math.round(tokens)), Math.max(0, usd));
}

/** Out-of-manifest attempts: this 10-minute window plus the previous one, so a burst across a boundary still counts. */
export async function recordOutOfManifest(agentId: string): Promise<number> {
  const now = Date.now();
  const b = tenMinuteBucket(now);
  const current = await bump(`oom:${agentId}:${b}`, now + 1_200_000);
  const previous = await read(`oom:${agentId}:${b - 1}`);
  return current.n + previous.n;
}

export async function eraseAgent(agentId: string): Promise<void> {
  await db.prepare("DELETE FROM shared_counter WHERE key LIKE ? OR key LIKE ? OR key LIKE ?").run(`rpm:${agentId}:%`, `day:${agentId}:%`, `oom:${agentId}:%`);
}

// --- Sign-in throttling -------------------------------------------------------------------------
// Failed administrator sign-ins are limited per client address and per administrator ID, so
// guessing the single administrator password is slow from one address and from many.
const LOGIN_WINDOW_MS = 15 * 60_000;
const MAX_FAILS_PER_ADDRESS = 10;
const MAX_FAILS_PER_ID = 20;

const loginKeys = (ip: string, username: string) => {
  const w = Math.floor(Date.now() / LOGIN_WINDOW_MS);
  return { ip: `login-ip:${ip}:${w}`, id: `login-id:${username.toLowerCase().slice(0, 200)}:${w}` };
};

export async function assertLoginAllowed(ip: string, username: string): Promise<void> {
  const k = loginKeys(ip, username);
  const [byIp, byId] = await Promise.all([read(k.ip), read(k.id)]);
  if (byIp.n >= MAX_FAILS_PER_ADDRESS || byId.n >= MAX_FAILS_PER_ID) {
    const retry = Math.ceil((LOGIN_WINDOW_MS - (Date.now() % LOGIN_WINDOW_MS)) / 1000);
    throw new PolicyError('RATE_LIMIT', `too many failed sign-in attempts; try again in ${Math.ceil(retry / 60)} minutes`, 429, { retry_after: retry });
  }
}

export async function recordLoginFailure(ip: string, username: string): Promise<void> {
  const k = loginKeys(ip, username);
  const expires = Date.now() + 2 * LOGIN_WINDOW_MS;
  await Promise.all([bump(k.ip, expires), bump(k.id, expires)]);
}

// --- Housekeeping ---------------------------------------------------------------------------------
/** Gateway nodes that stopped sending heartbeats: containers from earlier deploys or local runs. */
export const GATEWAY_LIVE_MS = 30_000;
export const GATEWAY_STALE_MS = 10 * 60_000;

export async function sweep(): Promise<void> {
  await db.prepare('DELETE FROM shared_counter WHERE expires_ms < ?').run(Date.now());
  await db.prepare('DELETE FROM gateway_node WHERE last_seen < ?').run(new Date(Date.now() - GATEWAY_STALE_MS).toISOString());
}
