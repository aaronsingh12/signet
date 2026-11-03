import { setTimeout } from 'node:timers/promises';
import { internal } from './state';

/** Send only policy-approved HTTP calls through an outbound connector worker. */
export async function forwardEdge(alias: string, action: string, args: Record<string, unknown>, workloadToken: string, signal: AbortSignal): Promise<unknown> {
  signal.throwIfAborted();
  const job = await internal<{ id: string }>('/internal/edge/jobs', {
    method: 'POST', body: JSON.stringify({ alias, action, args_json: JSON.stringify(args), workload_token: workloadToken }),
  });
  try {
    while (true) {
      signal.throwIfAborted();
      const result = await internal<{ state: string; result_json: string | null; error: string | null }>(`/internal/edge/jobs/${job.id}`);
      if (result.state === 'failed' || result.state === 'cancelled') throw new Error(`connector job ${job.id} ${result.state}: ${result.error}`);
      if (result.state === 'completed') {
        if (result.result_json === null) throw new TypeError(`connector job ${job.id} completed without a result`);
        return JSON.parse(result.result_json);
      }
      await setTimeout(250, undefined, { signal });
    }
  } finally {
    await internal(`/internal/edge/jobs/${job.id}`, { method: 'DELETE' });
  }
}
