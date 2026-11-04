/** Explicit platform contracts: paths must come from the platform's documented or observed schema. */
export interface ResponseMapping {
  items: string;
  id: string;
  name: string;
  status: string;
  timestamp: string;
}

export type ExternalOperation = 'test' | 'discover' | 'track' | 'executions' | 'run' | 'pause' | 'stop' | 'activate';
export interface ConnectionEndpoint { path: string; method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' }
export interface ExternalConnectionConfig {
  name: string;
  method: 'rest' | 'oauth' | 'hybrid';
  private_connector: { runner_id: string; tool_alias: string; environment: string } | null;
  base_url: string;
  auth: 'none' | 'api_key' | 'bearer' | 'oauth' | 'connector';
  header: string;
  client_id: string;
  token_url: string;
  scopes: string;
  token_auth: 'client_secret_basic' | 'client_secret_post';
  timeout_ms: number;
  sync_interval_seconds: number;
  remote_management: boolean;
  endpoints: Partial<Record<ExternalOperation, ConnectionEndpoint>>;
  agents_mapping: ResponseMapping | null;
  executions_mapping: ResponseMapping | null;
  tracking_pointer: string;
  execution_pagination: { total: string; offset: string; limit: string } | null;
}

/** Support Lab read schemas observed on 2026-11-03; prompts, responses and customer data are excluded. */
export function supportLabConnectionConfig(): ExternalConnectionConfig {
  return {
    name: 'Customer Support AI Agent', method: 'rest', private_connector: null,
    base_url: 'https://customer-support-ai-agent-roan.vercel.app/api/v1', auth: 'api_key', header: 'x-api-key',
    client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 15000,
    sync_interval_seconds: 300, remote_management: false,
    endpoints: {
      test: { method: 'GET', path: '/agents' }, discover: { method: 'GET', path: '/agents' },
      track: { method: 'GET', path: '/agents/{id}/track' }, executions: { method: 'GET', path: '/agents/executions?agentId={id}' },
      run: { method: 'POST', path: '/agents/{id}/run' }, pause: { method: 'POST', path: '/agents/{id}/pause' },
      stop: { method: 'POST', path: '/agents/{id}/stop' }, activate: { method: 'POST', path: '/agents/{id}/activate' },
    },
    agents_mapping: { items: '', id: '/id', name: '/name', status: '/status', timestamp: '/createdAt' },
    executions_mapping: { items: '/data', id: '/id', name: '', status: '/status', timestamp: '/createdAt' },
    tracking_pointer: '/agent',
    execution_pagination: { total: '/total', offset: '/offset', limit: '/limit' },
  };
}

export interface ConnectionHealth {
  reachable: boolean | null;
  authentication: 'unverified' | 'valid' | 'invalid' | 'not_required';
  discovered: number | null;
  monitoring: boolean;
  remote_control: boolean;
  gateway_enforcement: boolean;
  last_success_at: string | null;
  last_sync_at: string | null;
  last_error: string | null;
}
export interface ExternalConnectionView {
  id: string;
  agent_id: string | null;
  config: ExternalConnectionConfig;
  health: ConnectionHealth;
  state: 'enabled' | 'disconnected' | 'revoked';
  direction: 'outbound';
  capabilities: string[];
  coverage: 'external_monitoring' | 'gateway_tools';
  agent_count: number;
}
