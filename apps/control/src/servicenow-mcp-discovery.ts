import { request, type HttpResponse } from '@signet/core';
import { setTimeout } from 'node:timers/promises';
import { db, nowIso } from './db';
import { object, type Json } from './external-contract';
import { PolicyError } from './errors';
import { revealPlatformCredential } from './secrets';
import { tenant } from './tenant';

export interface ServiceNowTool { name: string; title: string; description: string }

async function readRpc(url: string, headers: Record<string, string>, message: Json): Promise<HttpResponse> {
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await request(url, { method: 'POST', headers, body: JSON.stringify(message), timeoutMs: 15000, maxBytes: 1024 * 1024, destination: { allowPrivate: false } });
      if (!response.ok) throw new PolicyError('SERVICENOW_MCP', `ServiceNow MCP discovery at ${url} returned HTTP ${response.status}; check OAuth permissions and reconnect if the token expired`, 502);
      return response;
    } catch (error) {
      if (attempt === 3 || error instanceof PolicyError) throw error;
      console.warn('ServiceNow MCP discovery failed; retrying', { attempt, endpoint: url });
      await setTimeout(200 * 2 ** (attempt - 1));
    }
  }
}

function rpcResult(response: HttpResponse, id: number): Record<string, Json> {
  const contentType = response.headers['content-type'] ?? '';
  const messages: Json[] = [];
  if (contentType.includes('text/event-stream')) {
    for (const event of response.text().split(/\r?\n\r?\n/)) {
      const data = event.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
      if (data) messages.push(JSON.parse(data) as Json);
    }
  } else if (contentType.includes('application/json')) messages.push(response.json<Json>());
  else throw new PolicyError('SERVICENOW_MCP', `ServiceNow MCP returned unsupported content type ${contentType}`, 502);
  for (const message of messages) {
    const envelope = object(message, 'ServiceNow MCP response');
    if (envelope.id !== id) continue;
    if (envelope.error) throw new PolicyError('SERVICENOW_MCP', 'ServiceNow MCP rejected discovery; verify server and tool ACLs', 502);
    return object(envelope.result, 'ServiceNow MCP result') as Record<string, Json>;
  }
  throw new PolicyError('SERVICENOW_MCP', `ServiceNow MCP response did not contain the requested JSON-RPC ID ${id}`, 502);
}

/** Discovers tool metadata only; never calls a business tool or enables agent monitoring. */
export async function discoverServiceNowTools(id: string): Promise<ServiceNowTool[]> {
  const row = await db.prepare('SELECT mcp_url, token_secret_id AS secret_id, expires_at FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ?').get(tenant.id, id) as { mcp_url: string; secret_id: string | null; expires_at: number | null } | undefined;
  if (!row || !row.secret_id || !row.expires_at || row.expires_at <= Date.now()) throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow authorization is missing or expired; reconnect before discovering tools', 409);
  const url = new URL(row.mcp_url);
  if (url.protocol !== 'https:' || !url.hostname.endsWith('.service-now.com') || url.port || url.username || url.password) throw new PolicyError('SERVICENOW_CONFIG', 'Saved MCP endpoint must be an HTTPS ServiceNow instance URL', 503);
  const credential = object(JSON.parse(await revealPlatformCredential(row.secret_id)) as Json, 'Stored ServiceNow credential');
  if (typeof credential.access_token !== 'string' || !credential.access_token) throw new PolicyError('SERVICENOW_AUTH', 'Stored ServiceNow access token is invalid; reconnect', 409);
  const headers: Record<string, string> = { authorization: `Bearer ${credential.access_token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  const initialized = await readRpc(url.href, headers, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'signet', version: '0.1.0' } } });
  const initialization = rpcResult(initialized, 1);
  if (typeof initialization.protocolVersion !== 'string') throw new PolicyError('SERVICENOW_MCP', 'ServiceNow MCP initialize response omitted protocolVersion', 502);
  headers['mcp-protocol-version'] = initialization.protocolVersion;
  const session = initialized.headers['mcp-session-id'];
  if (session) headers['mcp-session-id'] = session;
  await readRpc(url.href, headers, { jsonrpc: '2.0', method: 'notifications/initialized' });
  const tools: ServiceNowTool[] = [];
  const cursors = new Set<string>();
  let cursor: string | null = null;
  do {
    const result = rpcResult(await readRpc(url.href, headers, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: cursor ? { cursor } : {} }), 2);
    if (!Array.isArray(result.tools)) throw new PolicyError('SERVICENOW_MCP', 'ServiceNow tools/list response omitted the tools array', 502);
    for (const item of result.tools) {
      const tool = object(item, 'ServiceNow MCP tool');
      if (typeof tool.name !== 'string' || !tool.name || (tool.title !== undefined && typeof tool.title !== 'string') || (tool.description !== undefined && typeof tool.description !== 'string')) throw new PolicyError('SERVICENOW_MCP', 'ServiceNow tool metadata has invalid name, title or description', 502);
      tools.push({ name: tool.name, title: typeof tool.title === 'string' ? tool.title : tool.name, description: typeof tool.description === 'string' ? tool.description : '' });
    }
    if (result.nextCursor !== undefined && typeof result.nextCursor !== 'string') throw new PolicyError('SERVICENOW_MCP', 'ServiceNow tools/list nextCursor must be a string', 502);
    cursor = typeof result.nextCursor === 'string' ? result.nextCursor : null;
    if (cursor && (cursors.has(cursor) || cursors.size >= 99)) throw new PolicyError('SERVICENOW_MCP', 'ServiceNow tool discovery pagination repeated or exceeded 100 pages', 502);
    if (cursor) cursors.add(cursor);
  } while (cursor);
  await db.prepare('UPDATE servicenow_mcp_account SET tools_json = ?, discovered_at = ? WHERE tenant_id = ? AND id = ?').run(JSON.stringify(tools), nowIso(), tenant.id, id);
  return tools;
}
