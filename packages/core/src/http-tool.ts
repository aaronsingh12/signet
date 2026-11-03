import type { ToolAlias } from './types';

/** Resolve a registered HTTP action without allowing arguments to escape its base address. */
export function httpToolRequest(tool: ToolAlias, action: string, args: Record<string, unknown>, credential: string | null): {
  url: URL; method: string; headers: Record<string, string>; body: string | undefined;
} {
  const spec = tool.actions[action];
  if (!spec) throw new TypeError(`HTTP tool ${tool.alias} has no registered action ${action}`);
  const rest = { ...args };
  const path = spec.path.replace(/\{(\w+)\}/g, (_match, key: string) => {
    const value = String(rest[key] ?? '');
    delete rest[key];
    if (!value || value === '.' || value === '..') throw new TypeError(`HTTP tool ${tool.alias}: path parameter ${key} is empty or a dot segment`);
    return encodeURIComponent(value);
  });
  const base = new URL(tool.url);
  const url = new URL(tool.url.replace(/\/$/, '') + path);
  const prefix = base.pathname.replace(/\/$/, '');
  if (url.origin !== base.origin || (url.pathname !== prefix && !url.pathname.startsWith(`${prefix}/`))) throw new TypeError(`HTTP tool ${tool.alias}: action ${action} escapes the registered address`);
  const headers: Record<string, string> = { accept: 'application/json' };
  if (credential) headers[tool.auth_header] = tool.auth_header.toLowerCase() === 'authorization' ? `Bearer ${credential}` : credential;
  let body: string | undefined;
  if (spec.method === 'GET' || spec.method === 'DELETE') {
    for (const [key, value] of Object.entries(rest)) url.searchParams.set(key, String(value));
  } else {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(rest);
  }
  return { url, method: spec.method, headers, body };
}
