// Connector feature disabled at user request. Original code is preserved below.
// import type { ServiceNowRoutingView, ServiceNowRoutingAgent } from '@signet/core';
// import { db } from './db';
// import { PolicyError } from './errors';
// import { activeCertificate } from './registry';
// import { agentLevel } from './enforcement';
// import { GATEWAY_AUTH_ERRORS } from './gateway-auth';
// import { serviceNowGatewayRoute } from './servicenow-gateway';
// import { serviceNowSettings } from './servicenow-mcp-settings';
// import { rollouts } from './workflow';
// import { tenant } from './tenant';
//
// type Linked = { agent_id: string; name: string };
// type Evidence = { record_id: string; ts: string; instance_id: string | null; error_code: string | null; outcome: string | null };
// type Instance = { id: string; version: string };
//
// /** Only authenticated traffic to this connection's alias, using the current seal and identity, proves routing. */
// export async function serviceNowRouting(connectionId: string): Promise<ServiceNowRoutingView> {
//   const settings = await serviceNowSettings(connectionId);
//   if (!settings) throw new PolicyError('SERVICENOW_CONFIG', `ServiceNow connection ${connectionId} was not found in this tenant`, 404);
//   const route = await serviceNowGatewayRoute(connectionId);
//   const deployment = await rollouts();
//   const links = await db.prepare('SELECT l.agent_id, a.name FROM servicenow_agent_link l JOIN agent a ON a.id = l.agent_id WHERE l.connection_id = ? AND l.tenant_id = ? AND a.tenant_id = ? ORDER BY a.name').all(connectionId, tenant.id, tenant.id) as Linked[];
//   const agents = await Promise.all(links.map(async (link): Promise<ServiceNowRoutingAgent> => {
//     const cert = (await activeCertificate(link.agent_id))?.certificate ?? null;
//     const valid = cert !== null && Date.parse(cert.valid_from) <= Date.now() && Date.parse(cert.valid_to) > Date.now();
//     const actions = valid && route ? cert.tools.filter(tool => tool.server === `mcp://${route.alias}`).flatMap(tool => tool.actions.map(action => action.name)) : [];
//     const instances = await db.prepare('SELECT id, version FROM agent_instance WHERE agent_id = ? AND revoked_at IS NULL').all(link.agent_id) as Instance[];
//     const records = route && valid ? await db.prepare(`SELECT record_id, ts,
//         jsonb_extract_path_text(data::jsonb, 'instance_id') AS instance_id,
//         jsonb_extract_path_text(data::jsonb, 'error_code') AS error_code,
//         jsonb_extract_path_text(data::jsonb, 'outcome') AS outcome
//       FROM ledger_record WHERE tenant_id = ? AND agent_id = ? AND cert_id = ? AND kind = 'transaction'
//         AND jsonb_extract_path_text(data::jsonb, 'action_type') = 'tool_call'
//         AND jsonb_extract_path_text(data::jsonb, 'target') LIKE ? ORDER BY seq DESC LIMIT 100`).all(tenant.id, link.agent_id, cert.cert_id, `mcp://${route.alias}.%`) as Evidence[] : [];
//     const evidence = records.filter(record => instances.some(instance => instance.id === record.instance_id && instance.version === cert?.version) && (record.error_code === null || !GATEWAY_AUTH_ERRORS.includes(record.error_code)));
//     const level = await agentLevel(link.agent_id);
//     return { id: link.agent_id, name: link.name, certificate_id: valid ? cert.cert_id : null, environments: valid ? [...cert.environments] : [], allowed_actions: actions,
//       rollout: cert ? deployment[cert.cert_id]?.mode ?? 'enforce' : 'enforce', runtime_state: level,
//       routing_verified: valid && actions.length > 0 && evidence.length > 0 && !['killed', 'quarantined'].includes(level),
//       last_call_at: evidence[0]?.ts ?? null, last_block_at: evidence.find(record => record.outcome === 'blocked')?.ts ?? null, last_record_id: evidence[0]?.record_id ?? null };
//   }));
//   return { connection_id: connectionId, route, authorization_url: `${settings.gateway_url}/api/v1/identity/authorize`, token_url: `${settings.gateway_url}/api/v1/identity/token`, agents };
// }
