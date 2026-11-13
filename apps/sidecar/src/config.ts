import { readFileSync } from 'node:fs';
import { parseAgentConnectionFile } from '@signet/core';
import type { IdentityConfig } from './tokens';

/** Read the same UI-issued connection file used by the Python SDK. */
export function connectionFromFile(path: string): { gatewayUrl: string; identity: IdentityConfig } {
  const config = parseAgentConnectionFile(JSON.parse(readFileSync(path, 'utf8')));
  const source = config.identity;
  const identity: IdentityConfig = source.kind === 'oauth'
    ? { controlUrl: config.control_url, clientId: source.client_id, clientSecret: source.client_secret }
    : source.kind === 'bootstrap' ? { controlUrl: config.control_url, bootstrapCredential: source.credential }
    : { controlUrl: config.control_url, deploymentCredential: source.credential };
  return { gatewayUrl: config.gateway_url, identity };
}
