// Connector feature disabled at user request. Original code is preserved below.
// export interface ServiceNowRoutingAgent {
//   id: string;
//   name: string;
//   certificate_id: string | null;
//   environments: string[];
//   allowed_actions: string[];
//   rollout: 'shadow' | 'canary' | 'enforce';
//   runtime_state: string;
//   routing_verified: boolean;
//   last_call_at: string | null;
//   last_block_at: string | null;
//   last_record_id: string | null;
// }
//
// export interface ServiceNowRoutingView {
//   connection_id: string;
//   route: { alias: string; url: string } | null;
//   authorization_url: string;
//   token_url: string;
//   agents: ServiceNowRoutingAgent[];
// }
