export type ConnectionIdentity =
  | { kind: 'bootstrap'; credential: string }
  | { kind: 'oauth'; client_id: string; client_secret: string }
  | { kind: 'gateway'; credential: string };
export interface AgentConnectionFile { version: 1; control_url: string; gateway_url: string; identity: ConnectionIdentity; token_cache: string | null }

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`Agent configuration requires ${field} as a non-empty string`);
  return value.trim();
}

/** Accept only the versioned connection file issued by the onboarding UI. */
export function parseAgentConnectionFile(value: unknown): AgentConnectionFile {
  if (!value || typeof value !== 'object' || !('version' in value) || value.version !== 1 || !('identity' in value) || !('control_url' in value) || !('gateway_url' in value) || !('token_cache' in value)) throw new TypeError('Agent configuration must contain version 1, identity, control_url, gateway_url and token_cache');
  const control = new URL(text(value.control_url, 'control_url'));
  const gateway = new URL(text(value.gateway_url, 'gateway_url'));
  for (const url of [control, gateway]) {
    if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new TypeError('Agent connection URLs must be HTTPS service origins; HTTP is allowed only on localhost');
  }
  const source = value.identity;
  if (!source || typeof source !== 'object' || !('kind' in source)) throw new TypeError('Agent configuration requires an identity kind');
  let identity: ConnectionIdentity;
  if ((source.kind === 'bootstrap' || source.kind === 'gateway') && 'credential' in source) identity = { kind: source.kind, credential: text(source.credential, 'identity.credential') };
  else if (source.kind === 'oauth' && 'client_id' in source && 'client_secret' in source) identity = { kind: 'oauth', client_id: text(source.client_id, 'identity.client_id'), client_secret: text(source.client_secret, 'identity.client_secret') };
  else throw new TypeError('Agent identity must contain bootstrap/gateway credential or OAuth client_id and client_secret');
  return { version: 1, control_url: control.origin, gateway_url: gateway.origin, identity, token_cache: value.token_cache === null ? null : text(value.token_cache, 'token_cache') };
}
