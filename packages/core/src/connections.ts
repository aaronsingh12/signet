/** Explicit platform contracts: paths must come from the platform's documented or observed schema. */
export interface ResponseMapping {
  items: string;
  id: string;
  name: string;
  status: string;
  timestamp: string;
  fields?: Record<string, string>;
}

export type ExternalOperation = 'test' | 'discover' | 'agent' | 'track' | 'executions' | 'execution' | 'logs' | 'metrics' | 'run' | 'pause' | 'stop' | 'activate';
export type ConnectorJson = null | boolean | number | string | ConnectorJson[] | { [key: string]: ConnectorJson };
export interface ConnectionEndpoint {
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  variables?: Record<string, 'id' | 'execution_id'>;
  query?: Record<string, string>;
  request_body?: ConnectorJson;
  expected_status?: number[];
  response_schema?: { [key: string]: ConnectorJson };
  response_path?: string;
  idempotency_header?: string;
}

export interface ExternalConnectionConfig {
  name: string;
  method: 'rest' | 'oauth' | 'hybrid';
  private_connector: { runner_id: string; tool_alias: string; environment: string } | null;
  base_url: string;
  auth: 'none' | 'api_key' | 'api_key_query' | 'basic' | 'custom_headers' | 'bearer' | 'oauth' | 'connector';
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
  discovery_pagination?: { total: string; offset: string; limit: string } | null;
  provider_type?: 'generic_rest';
  username?: string;
  secret_headers?: string[];
  query_key_acknowledged?: boolean;
  monitoring_enabled?: boolean;
  tls_min_version?: 'TLSv1.2' | 'TLSv1.3';

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
  last_tested_at?: string | null;
  endpoint_verified?: boolean;
  error_category?: string | null;
  verified_operations?: string[];
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
  mapped_agent_ids: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
  configuration_status: 'configured' | 'verified' | 'disconnected' | 'revoked';
}
