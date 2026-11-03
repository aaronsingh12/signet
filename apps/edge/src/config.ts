import { readFileSync } from 'node:fs';
import type { ToolAlias } from '@signet/core';

export interface LocalTool { tool: ToolAlias; tokenEnv: string | null }
export interface EdgeConfig { controlUrl: string; runnerId: string; secret: string; tools: LocalTool[] }

function object(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function requiredText(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${field} must be a non-empty string`);
  return value.trim();
}

/** Load an explicit local allowlist. Neither the cloud nor an agent can supply new destinations. */
export function parseTools(value: unknown): LocalTool[] {
  if (!Array.isArray(value) || !value.length) throw new TypeError('edge tools file must contain a non-empty array of HTTP tool definitions');
  const tools = value.map((entry: unknown, index: number): LocalTool => {
    const source = object(entry, `tools[${index}]`);
    const alias = requiredText(source.alias, 'alias');
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(alias)) throw new TypeError(`tool ${alias}: alias must be kebab-case`);
    const url = new URL(requiredText(source.url, `${alias}.url`));
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new TypeError(`tool ${alias}: URL must be HTTP(S) without credentials, query or fragment`);
    const actionSource = object(source.actions, `${alias}.actions`);
    const actions: ToolAlias['actions'] = {};
    for (const [name, entry] of Object.entries(actionSource)) {
      const action = object(entry, `${alias}.${name}`);
      const method = requiredText(action.method, `${alias}.${name}.method`);
      const path = requiredText(action.path, `${alias}.${name}.path`);
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) || !path.startsWith('/') || /(^|\/)\.{1,2}(\/|$)|\/\/|[?#]/.test(path)) throw new TypeError(`tool ${alias}: invalid method or path for action ${name}`);
      actions[name] = { method, path };
    }
    if (!Object.keys(actions).length) throw new TypeError(`tool ${alias}: at least one action is required`);
    const header = source.auth_header === undefined ? 'authorization' : requiredText(source.auth_header, `${alias}.auth_header`);
    if (!/^[a-zA-Z0-9-]+$/.test(header) || ['host', 'content-length', 'connection', 'transfer-encoding'].includes(header.toLowerCase())) throw new TypeError(`tool ${alias}: invalid credential header ${header}`);
    const tokenEnv = source.token_env === undefined ? null : requiredText(source.token_env, `${alias}.token_env`);
    return { tool: { alias, kind: 'http', url: url.toString().replace(/\/$/, ''), actions, auth_header: header, secret_id: null }, tokenEnv };
  });
  if (new Set(tools.map((item) => item.tool.alias)).size !== tools.length) throw new TypeError('edge tools file contains duplicate aliases');
  return tools;
}

export function configFromEnv(env: NodeJS.ProcessEnv): EdgeConfig {
  const controlUrl = new URL(requiredText(env.SIGNET_CONTROL_URL, 'SIGNET_CONTROL_URL'));
  if (controlUrl.protocol !== 'https:' && !(controlUrl.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(controlUrl.hostname))) throw new TypeError('SIGNET_CONTROL_URL must use HTTPS; HTTP is allowed only for local development');
  const file = requiredText(env.SIGNET_EDGE_TOOLS_FILE, 'SIGNET_EDGE_TOOLS_FILE');
  return {
    controlUrl: controlUrl.toString().replace(/\/$/, ''),
    runnerId: requiredText(env.SIGNET_EDGE_RUNNER_ID, 'SIGNET_EDGE_RUNNER_ID'),
    secret: requiredText(env.SIGNET_EDGE_RUNNER_SECRET, 'SIGNET_EDGE_RUNNER_SECRET'),
    tools: parseTools(JSON.parse(readFileSync(file, 'utf8'))),
  };
}
