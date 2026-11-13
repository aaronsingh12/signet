import { db, nowIso, tx } from './db';
import { invalid } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

export interface ConnectionAddresses {
  control_url: string;
  gateway_url: string | null;
  control_url_source: string;
  gateway_url_source: string;
}

function address(value: string, field: string): string {
  if (typeof value !== 'string' || !value.trim()) throw invalid(`${field} must be an absolute HTTPS address`);
  let url: URL;
  try { url = new URL(value.trim()); } catch { throw invalid(`${field} must be an absolute HTTPS address`); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) || url.username || url.password || url.search || url.hash) throw invalid(`${field} must use HTTPS without credentials, query or fragment; HTTP is allowed only on localhost`);
  if (url.pathname !== '/') throw invalid(`${field} must be the service origin, without /api or /v1`);
  return url.origin;
}

/** Read each request from PostgreSQL so hosted instances immediately use UI changes. Existing environment configuration remains valid until settings are saved. */
export async function connectionAddresses(): Promise<ConnectionAddresses> {
  const saved = await db.prepare('SELECT control_url, gateway_url FROM connection_settings WHERE tenant_id = ?').get(tenant.id) as { control_url: string; gateway_url: string } | undefined;
  if (saved) return { ...saved, control_url_source: 'database', gateway_url_source: 'database' };
  const nodes = await db.prepare('SELECT id, url, last_seen FROM gateway_node ORDER BY id').all() as { id: string; url: string; last_seen: string }[];
  const live = nodes.find((node) => Date.now() - Date.parse(node.last_seen) < 30_000);
  const gateway = process.env.SIGNET_GATEWAY_PUBLIC_URL ?? process.env.SIGNET_GATEWAY_URL ?? live?.url ?? null;
  return {
    control_url: (process.env.SIGNET_CONTROL_PUBLIC_URL ?? `http://localhost:${process.env.SIGNET_CONTROL_PORT ?? '4100'}`).replace(/\/+$/, ''),
    gateway_url: gateway?.replace(/\/+$/, '') ?? null,
    control_url_source: process.env.SIGNET_CONTROL_PUBLIC_URL ? 'deployment configuration' : 'local development address',
    gateway_url_source: process.env.SIGNET_GATEWAY_PUBLIC_URL || process.env.SIGNET_GATEWAY_URL ? 'deployment configuration' : live ? `gateway node ${live.id} (local address)` : 'not configured',
  };
}

export async function saveConnectionAddresses(input: { control_url: string; gateway_url: string }, actor: Principal): Promise<ConnectionAddresses> {
  const control = address(input.control_url, 'control_url');
  const gateway = address(input.gateway_url, 'gateway_url');
  await tx(async () => {
    await db.prepare('INSERT INTO connection_settings (tenant_id, control_url, gateway_url, updated_at, updated_by) VALUES (?, ?, ?, ?, ?) ON CONFLICT (tenant_id) DO UPDATE SET control_url = excluded.control_url, gateway_url = excluded.gateway_url, updated_at = excluded.updated_at, updated_by = excluded.updated_by').run(tenant.id, control, gateway, nowIso(), actor.id);
    await ledger.append({ kind: 'admin', data: { event: 'connection.addresses_saved', control_url: control, gateway_url: gateway, actor: actor.id } });
  });
  return connectionAddresses();
}

export async function gatewayAddress(): Promise<string> {
  const settings = await connectionAddresses();
  if (!settings.gateway_url) throw invalid('Save the Gateway URL under Hosted Signet addresses in the connection setup before connecting an agent');
  return settings.gateway_url;
}
