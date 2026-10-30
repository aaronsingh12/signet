import type { ToolAlias } from '@signet/core';
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
}

const toAlias = (r: Row): ToolAlias => ({ alias: r.alias, kind: r.kind, url: r.url, secret_id: r.secret_id, auth_header: r.auth_header, actions: JSON.parse(r.actions) });

export function getTool(alias: string): ToolAlias | null {
  const r = db.prepare('SELECT alias, kind, url, secret_id, auth_header, actions FROM tool WHERE tenant_id = ? AND alias = ?').get(tenant.id, alias) as Row | undefined;
  return r ? toAlias(r) : null;
}

export const listTools = () => (db.prepare('SELECT alias, kind, url, secret_id, auth_header, actions FROM tool WHERE tenant_id = ? ORDER BY alias').all(tenant.id) as unknown as Row[]).map(toAlias);

export interface ToolInput {
  alias: string;
  kind: 'mcp' | 'http';
  url: string;
  secret?: string | null; // secret id or name in the broker
  auth_header?: string;
  actions?: Record<string, { method: string; path: string }>;
}

export function registerTool(input: ToolInput, p: Principal): ToolAlias {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.alias ?? '')) throw invalid('alias must be kebab-case');
  if (!['mcp', 'http'].includes(input.kind)) throw invalid('kind must be mcp or http');
  let url: URL;
  try {
    url = new URL(input.url);
  } catch {
    throw invalid('url is not a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw invalid('url must be http or https');
  const actions = input.actions ?? {};
  if (input.kind === 'http') {
    if (!Object.keys(actions).length) throw invalid('http tools need an actions map: { name: { method, path } }');
    for (const [name, a] of Object.entries(actions)) {
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(a.method)) throw invalid(`action ${name}: unsupported method`);
      if (!a.path?.startsWith('/')) throw invalid(`action ${name}: path must start with /`);
    }
  }
  const secretId = input.secret ? getSecretMeta(input.secret).id : null;
  return tx(() => {
    if (getTool(input.alias)) throw new PolicyError('VALIDATION', `tool alias ${input.alias} exists`, 409);
    db.prepare('INSERT INTO tool (alias, tenant_id, kind, url, secret_id, auth_header, actions, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      input.alias, tenant.id, input.kind, url.toString().replace(/\/$/, ''), secretId, input.auth_header ?? 'authorization', JSON.stringify(actions), p.id, nowIso(),
    );
    ledger.append({ kind: 'admin', data: { event: 'tool.registered', alias: input.alias, kind: input.kind, url: url.origin, secret_id: secretId, actor: p.id } });
    return getTool(input.alias)!;
  });
}
