import { DestinationBlocked, checkDestination, destinationPolicyFromEnv, type ToolAlias } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { getSecretMeta } from './secrets';
import { tenant } from './tenant';

// Tool aliases (BP 5.1, 11.2): agents call /v1/mcp/<alias> or /v1/tools/http/<alias>/<action>.
// The real address and its credential live only here and in the gateway.

interface Row {
  alias: string;
  kind: 'mcp' | 'http';
  url: string;
  secret_id: string | null;
  auth_header: string;
  actions: string;
  runner_id: string | null;
}

const toAlias = (r: Row): ToolAlias => ({ alias: r.alias, kind: r.kind, url: r.url, secret_id: r.secret_id, auth_header: r.auth_header, actions: JSON.parse(r.actions), runner_id: r.runner_id });

export async function getTool(alias: string): Promise<ToolAlias | null> {
  const r = (await db.prepare('SELECT alias, kind, url, secret_id, auth_header, actions, runner_id FROM tool WHERE tenant_id = ? AND alias = ?').get(tenant.id, alias)) as Row | undefined;
  return r ? toAlias(r) : null;
}

export const listTools = async () => ((await db.prepare('SELECT alias, kind, url, secret_id, auth_header, actions, runner_id FROM tool WHERE tenant_id = ? ORDER BY alias').all(tenant.id)) as unknown as Row[]).map(toAlias);

export interface ToolInput {
  alias: string;
  kind: 'mcp' | 'http';
  url: string;
  secret?: string | null; // secret id or name in the broker
  auth_header?: string;
  actions?: Record<string, { method: string; path: string }>;
  runner_id?: string | null;
}

// The address must resolve to somewhere tools may reach (no cloud metadata, no private networks unless
// SIGNET_TOOL_PRIVATE_DESTINATIONS=allow). The gateway checks again on every connection.
export async function registerTool(input: ToolInput, p: Principal): Promise<ToolAlias> {
  if (input.runner_id !== undefined && input.runner_id !== null && typeof input.runner_id !== 'string') throw invalid('runner_id must be a runner ID string');
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.alias ?? '')) throw invalid('alias must be kebab-case');
  if (!['mcp', 'http'].includes(input.kind)) throw invalid('kind must be mcp or http');
  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    throw invalid('url is not a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw invalid('url must be http or https');
  if (url.username || url.password || url.search || url.hash) throw invalid('tool URL must not contain credentials, query parameters or a fragment');
  if (input.runner_id) {
    if (input.kind !== 'http') throw invalid('connector runners support HTTP tools; MCP tools connect directly to the gateway');
    if (input.secret && (await getSecretMeta(input.secret)).kind !== 'tool') throw invalid('runner tools require a tool credential from Secrets Broker');
    const runner = (await db.prepare('SELECT id FROM edge_runner WHERE id = ? AND tenant_id = ? AND revoked_at IS NULL').get(input.runner_id, tenant.id));
    if (!runner) throw invalid(`runner ${input.runner_id} is unknown or revoked`);
  }
  try {
    if (!input.runner_id) await checkDestination(url, destinationPolicyFromEnv());
  } catch (e) {
    if (e instanceof DestinationBlocked) throw new PolicyError('SSRF', e.message, 422);
    throw e;
  }
  const actions = input.actions ?? {};
  if (input.kind === 'http') {
    if (!Object.keys(actions).length) throw invalid('http tools need an actions map: { name: { method, path } }');
    for (const [name, a] of Object.entries(actions)) {
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(a.method)) throw invalid(`action ${name}: unsupported method`);
      if (!a.path?.startsWith('/')) throw invalid(`action ${name}: path must start with /`);
      if (/(^|\/)\.{1,2}(\/|$)|\/\/|[?#]/.test(a.path)) throw invalid(`action ${name}: path may not contain dot segments, //, ? or #`);
    }
  }
  const secretId = input.secret ? (await getSecretMeta(input.secret)).id : null;
  return (await tx(async () => {
    if ((await getTool(input.alias))) throw new PolicyError('VALIDATION', `tool alias ${input.alias} exists`, 409);
    (await db.prepare('INSERT INTO tool (alias, tenant_id, kind, url, secret_id, auth_header, actions, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      input.alias, tenant.id, input.kind, url.toString().replace(/\/$/, ''), secretId, input.auth_header ?? 'authorization', JSON.stringify(actions), p.id, nowIso(),
    ));
    (await db.prepare('UPDATE tool SET runner_id = ? WHERE alias = ? AND tenant_id = ?').run(input.runner_id ?? null, input.alias, tenant.id));
    (await ledger.append({ kind: 'admin', data: { event: 'tool.registered', alias: input.alias, kind: input.kind, url: url.origin, secret_id: secretId, actor: p.id, runner_id: input.runner_id ?? null } }));
    return (await getTool(input.alias))!;
  }));
}
