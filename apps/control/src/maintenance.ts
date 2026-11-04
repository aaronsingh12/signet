import { setTimeout } from 'node:timers/promises';
import { devSecret } from '@signet/core';

/** Vercel daemon keeps maintenance running while the HTTP services scale to zero. */
const controlUrl = process.env.SIGNET_CONTROL_URL?.replace(/\/+$/, '');
if (!controlUrl) throw new Error('SIGNET_CONTROL_URL service binding is required for the maintenance daemon');
const token = devSecret('SIGNET_INTERNAL_TOKEN');
const jobs: ReadonlyArray<{ name: string; interval: number; timeout: number }> = [
  { name: 'ladder', interval: 15_000, timeout: 120000 },
  { name: 'approvals', interval: 5_000, timeout: 120000 },
  { name: 'lifecycle', interval: 600_000, timeout: 120000 },
  { name: 'controls', interval: 600_000, timeout: 120000 },
  { name: 'connectors', interval: 3_000, timeout: 120000 },
  { name: 'connections', interval: 30_000, timeout: 600000 },
  { name: 'edge', interval: 10_000, timeout: 120000 },
  { name: 'roots', interval: 600_000, timeout: 120000 },
  { name: 'platform-usage', interval: 6 * 3_600_000, timeout: 120000 },
  { name: 'counters', interval: 60_000, timeout: 120000 },
];

async function invokeJob(name: string, timeout: number): Promise<void> {
  const url = `${controlUrl}/internal/maintenance/${name}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url, { method: 'POST', headers: { 'x-signet-internal': token }, signal: AbortSignal.timeout(timeout) });
      if (!response.ok) throw new Error(`Maintenance POST ${url} failed (${response.status}): ${await response.text()}`);
      return;
    } catch (error) {
      if (attempt === 3) throw error;
      console.warn('Maintenance request failed; retrying', { job: name, attempt, error });
      await setTimeout(attempt * 1000);
    }
  }
}

const nextRun = new Map<string, number>();
while (true) {
  for (const job of jobs) {
    if (Date.now() < (nextRun.get(job.name) ?? 0)) continue;
    await invokeJob(job.name, job.timeout);
    nextRun.set(job.name, Date.now() + job.interval);
  }
  await setTimeout(1000);
}
