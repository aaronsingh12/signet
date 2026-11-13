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
  { name: 'ownerless', interval: 600_000, timeout: 120000 },
  { name: 'aibom', interval: 24 * 3_600_000, timeout: 600000 },
  { name: 'baselines', interval: 24 * 3_600_000, timeout: 600000 },
];

async function invokeJob(name: string, timeout: number): Promise<void> {
  const url = `${controlUrl}/internal/maintenance/${name}`;
  await invokeMaintenance(url, { 'x-signet-internal': token }, timeout, name);
}

async function invokeMaintenance(url: string, headers: Record<string, string>, timeout: number, name: string): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url, { method: 'POST', headers, signal: AbortSignal.timeout(timeout) });
      if (!response.ok) throw new Error(`Maintenance POST ${url} failed (${response.status}): ${await response.text()}`);
      return;
    } catch (error) {
      if (attempt === 3) throw error;
      console.warn('Maintenance request failed; retrying', { job: name, attempt, error });
      await setTimeout(attempt * 1000);
    }
  }
}

async function runMaintenance(): Promise<never> {
  const nextRun = new Map<string, number>();
  while (true) {
    for (const job of jobs) {
      if (Date.now() < (nextRun.get(job.name) ?? 0)) continue;
      await invokeJob(job.name, job.timeout);
      nextRun.set(job.name, Date.now() + job.interval);
    }
    await setTimeout(1000);
  }
}

/** Renew a serverless agent's shared workload identity independently of long-running maintenance jobs. */
async function renewWorkloadIdentity(url: string, refreshToken: string): Promise<never> {
  while (true) {
    await invokeMaintenance(url, { 'x-signet-workload-refresh': refreshToken }, 30_000, 'workload-identity');
    await setTimeout(60_000);
  }
}

const refreshUrl = process.env.SIGNET_WORKLOAD_REFRESH_URL;
const refreshToken = process.env.SIGNET_WORKLOAD_REFRESH_TOKEN;
if (Boolean(refreshUrl) !== Boolean(refreshToken)) throw new Error('SIGNET_WORKLOAD_REFRESH_URL and SIGNET_WORKLOAD_REFRESH_TOKEN must both be configured');
await Promise.all([
  runMaintenance(),
  ...(refreshUrl && refreshToken ? [renewWorkloadIdentity(refreshUrl, refreshToken)] : []),
]);
