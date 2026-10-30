import type { Response } from 'express';

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
