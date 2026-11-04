import type { Response } from 'express';
import { newId } from '@signet/core';
import { PolicyError } from './errors';

// Push channel to gateway nodes (Server-Sent Events). Stands in for the NATS event bus of BP 3
// in the dev profile; gateways also poll the bundle every 5 s, so a missed push cannot keep an
// agent alive (BP 5.4).
const nodes = new Map<string, Response>();

export function attach(nodeId: string, res: Response) {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
  res.write(': connected\n\n');
  nodes.set(nodeId, res);
  const ping = setInterval(() => res.write(': ping\n\n'), 15_000);
  res.on('close', () => {
    clearInterval(ping);
    if (nodes.get(nodeId) === res) nodes.delete(nodeId);
  });
}

export function publish(type: string, data: Record<string, unknown>) {
  const frame = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of nodes.values()) res.write(frame);
}

export const connectedNodes = () => [...nodes.keys()];

interface ErasureRequest { expected: Set<string>; complete: () => void }
const erasures = new Map<string, ErasureRequest>();

/** Require every connected gateway to discard the agent before its persisted records are erased. */
export async function eraseAgentOnGateways(agentId: string, sessions: string[], instances: string[], tokens: string[], expected: string[]): Promise<void> {
  if (!expected.length) return;
  const requestId = newId('evt');
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      const missing = [...(erasures.get(requestId)?.expected ?? [])];
      erasures.delete(requestId);
      reject(new PolicyError('ERASURE_GATEWAY', `Agent data was not deleted: gateways ${missing.join(', ')} did not confirm cleanup. The agent is stopped; reconnect these gateways and retry deletion.`, 503));
    }, 10_000);
    erasures.set(requestId, { expected: new Set(expected), complete: () => { clearTimeout(timer); erasures.delete(requestId); resolve(); } });
    publish('agent.erase', { request_id: requestId, agent_id: agentId, sessions, instances, tokens });
  });
}

export function acknowledgeAgentErasure(requestId: string, nodeId: string): void {
  const request = erasures.get(requestId);
  if (!request) return;
  request.expected.delete(nodeId);
  if (!request.expected.size) request.complete();
}
