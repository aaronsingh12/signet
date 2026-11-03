import { setTimeout } from 'node:timers/promises';
import { destinationPolicyFromEnv, httpToolRequest, request, type EdgeTask, type HttpResponse } from '@signet/core';
import type { EdgeConfig } from './config';

class ControlError extends Error {
  constructor(readonly status: number, method: string, path: string, body: string) {
    super(`edge control request ${method} ${path} failed (${status}): ${body}`);
  }
}

/** Retry only control-plane transport operations, never the private API operation itself. */
async function control(config: EdgeConfig, path: string, method: string, body: string | undefined, signal: AbortSignal): Promise<HttpResponse> {
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await request(`${config.controlUrl}/api/v1/edge/runners/${encodeURIComponent(config.runnerId)}${path}`, {
        method, body, headers: { authorization: `Bearer ${config.secret}`, 'content-type': 'application/json' }, signal, timeoutMs: 5_000, maxBytes: 1024 * 1024,
      });
      if (!response.ok) throw new ControlError(response.status, method, path, response.text());
      return response;
    } catch (error) {
      if (signal.aborted || attempt >= 3 || (error instanceof ControlError && error.status < 500)) throw error;
      console.warn('edge control request failed; retrying', { path, method, attempt, error: error instanceof Error ? error.message : String(error) });
      await setTimeout(attempt * 300, undefined, { signal });
    }
  }
}

function parseTask(value: unknown): EdgeTask | null {
  if (!value || typeof value !== 'object' || !('task' in value)) throw new TypeError('runner poll response must contain task');
  if (value.task === null) return null;
  const task = value.task;
  if (!task || typeof task !== 'object' || !('id' in task) || typeof task.id !== 'string' || !('alias' in task) || typeof task.alias !== 'string' || !('action' in task) || typeof task.action !== 'string' || !('args_json' in task) || typeof task.args_json !== 'string' || !('expires_at' in task) || typeof task.expires_at !== 'string' || !Number.isFinite(Date.parse(task.expires_at))) throw new TypeError('runner task requires id, alias, action, args_json and a valid expires_at');
  if (!('target' in task) || !task.target || typeof task.target !== 'object' || !('url' in task.target) || typeof task.target.url !== 'string' || !('method' in task.target) || typeof task.target.method !== 'string' || !('path' in task.target) || typeof task.target.path !== 'string') throw new TypeError('runner task target requires url, method and path');
  return { id: task.id, alias: task.alias, action: task.action, args_json: task.args_json, expires_at: task.expires_at, target: { url: task.target.url, method: task.target.method, path: task.target.path } };
}

async function monitorLease(config: EdgeConfig, taskId: string, controller: AbortController): Promise<void> {
  try {
    while (!controller.signal.aborted) {
      await control(config, `/jobs/${encodeURIComponent(taskId)}/lease`, 'GET', undefined, controller.signal);
      await setTimeout(1000, undefined, { signal: controller.signal });
    }
  } catch (error) {
    if (!controller.signal.aborted) controller.abort(error);
  }
}

/** Execute only a local allowlisted action, with per-connection SSRF checks and local credentials. */
export async function executeTask(config: EdgeConfig, task: EdgeTask, signal: AbortSignal): Promise<string> {
  const local = config.tools.find((item) => item.tool.alias === task.alias);
  if (!local) throw new TypeError(`runner ${config.runnerId}: tool ${task.alias} is not in the local allowlist`);
  const action = local.tool.actions[task.action];
  if (local.tool.url !== task.target.url || !action || action.method !== task.target.method || action.path !== task.target.path) throw new TypeError(`tool ${task.alias}.${task.action}: local URL, method and path must match its registered configuration`);
  const remaining = Date.parse(task.expires_at) - Date.now();
  if (remaining <= 0) throw new Error(`connector job ${task.id} expired before execution; it will not be replayed`);
  const args: unknown = JSON.parse(task.args_json);
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new TypeError(`connector job ${task.id}: arguments must be an object`);
  const credential = local.tokenEnv ? process.env[local.tokenEnv] : null;
  if (local.tokenEnv && !credential) throw new TypeError(`tool ${task.alias}: credential environment variable ${local.tokenEnv} is missing`);
  const target = httpToolRequest(local.tool, task.action, args as Record<string, unknown>, credential ?? null);
  const controller = new AbortController();
  const abort = (): void => controller.abort(signal.reason);
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  await control(config, `/jobs/${encodeURIComponent(task.id)}/lease`, 'GET', undefined, controller.signal);
  const monitor = monitorLease(config, task.id, controller);
  try {
    const response = await request(target.url, {
      method: target.method, headers: target.headers, body: target.body,
      destination: destinationPolicyFromEnv(), maxBytes: 512 * 1024,
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(remaining)]), timeoutMs: remaining,
    });
    if (!response.ok) throw new Error(`private tool ${task.alias}.${task.action}: ${target.method} ${target.url.pathname} returned ${response.status}: ${response.text()}`);
    const text = response.text();
    if ((response.headers['content-type'] ?? '').includes('json')) return JSON.stringify(JSON.parse(text));
    return JSON.stringify({ text });
  } finally {
    controller.abort();
    signal.removeEventListener('abort', abort);
    await monitor;
  }
}

/** The runner opens outbound requests only. Each claimed operation executes at most once. */
export async function run(config: EdgeConfig, signal: AbortSignal): Promise<void> {
  while (!signal.aborted) {
    const response = await control(config, '/poll', 'POST', '{}', signal);
    const task = parseTask(response.json<unknown>());
    if (!task) {
      await setTimeout(1000, undefined, { signal });
      continue;
    }
    let outcome: { result_json: string } | { error: string };
    try {
      outcome = { result_json: await executeTask(config, task, signal) };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.error('private connector action failed', { job_id: task.id, alias: task.alias, action: task.action, error: detail });
      outcome = { error: detail };
    }
    try {
      await control(config, `/jobs/${encodeURIComponent(task.id)}/result`, 'POST', JSON.stringify(outcome), signal);
    } catch (error) {
      if (!(error instanceof ControlError) || ![403, 409, 410].includes(error.status)) throw error;
      // A cancelled, expired or revoked agent job must not stop unrelated agents on this runner.
      console.warn('connector job result rejected; operation will not be replayed', { job_id: task.id, status: error.status, error: error.message });
    }
  }
}
