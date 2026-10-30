import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REPO_ROOT, type DetectorResult, type Tier } from '@signet/core';
import * as state from './state';

// Detector runtime (DA 3, E38). Detectors run in a separate, stateless process: they get text and
// return a score, with no tools, no memory between calls and no instruction channel (DA 6 mechanism 5).
// The process starts under Node's permission model with read-only access to the model files.
// Network isolation is enforced by the deployment (Kubernetes NetworkPolicy); the dev process has no
// network code. A detector that is off, warming up, or over its latency budget reports unavailable
// (RB-INV-06, RB-LAT-07). Shadow detectors score and log but never change a decision (RB-MOD-03).

const MODEL_DIR = join(REPO_ROOT, 'models', 'deberta-injection');
const DA_BUDGET_MS = 15; // DA 3 p95 budget for DET-INJ
// deberta-v3-base (fp32) takes 70-200 ms on a 4-core CPU, far over the DA 3 budget, so the gateway
// never waits for it inline: tool responses are scored right after they return, and prompts are
// scored while the cloud LLM call is in flight. A result that has not arrived within this cap counts
// as unavailable. A smaller fine-tuned model (E39) or a GPU pool (RB-LAT-05) restores the inline path.
const CAP_MS = Number(process.env.SIGNET_DET_INJ_CAP_MS ?? 3000);

// Rulebook starting thresholds, DET-INJ (Elevated / High).
const INJ_PROMPT: Record<Tier, [number, number]> = { T1: [0.5, 0.8], T2: [0.6, 0.85], T3: [0.7, 0.9], T4: [0.8, 0.95] };
const INJ_TOOL: Record<Tier, [number, number]> = { T1: [0.4, 0.7], T2: [0.5, 0.8], T3: [0.6, 0.85], T4: [0.7, 0.9] };

let child: ChildProcess | null = null;
let ready = false;
let seq = 0;
const waiting = new Map<number, (r: { score?: number; ms?: number; error?: string }) => void>();
export let modelInfo = 'not loaded';

export function startRuntime() {
  if (process.env.SIGNET_DET_RUNTIME === 'off') {
    modelInfo = 'disabled on this node (SIGNET_DET_RUNTIME=off)';
    return;
  }
  if (!existsSync(join(MODEL_DIR, 'onnx'))) {
    modelInfo = `no model files in ${MODEL_DIR}`;
    return;
  }
  const worker = join(dirname(fileURLToPath(import.meta.url)), 'detector-worker.mjs');
  const nm = join(REPO_ROOT, 'node_modules');
  child = spawn(process.execPath, ['--permission', `--allow-fs-read=${MODEL_DIR}`, `--allow-fs-read=${nm}`, `--allow-fs-read=${worker}`, '--allow-addons', worker, MODEL_DIR], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: { PATH: process.env.PATH ?? '', SYSTEMROOT: process.env.SYSTEMROOT ?? '' }, // no secrets in the detector's environment
  });
  let buf = '';
  child.stdout!.on('data', (d: Buffer) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      const msg = JSON.parse(line) as { id?: number; ready?: boolean; info?: string; score?: number; ms?: number; error?: string };
      if (msg.ready) {
        ready = true;
        modelInfo = msg.info ?? 'ready';
        console.log(`[gateway] detector runtime ready: ${modelInfo}`);
      } else if (msg.id !== undefined) {
        waiting.get(msg.id)?.(msg);
        waiting.delete(msg.id);
      }
    }
  });
  child.on('exit', (code) => {
    ready = false;
    modelInfo = `detector runtime exited (${code})`;
    for (const fn of waiting.values()) fn({ error: 'runtime exited' });
    waiting.clear();
  });
}

function score(text: string, budgetMs: number): Promise<{ score?: number; ms?: number; error?: string }> {
  if (!child || !ready) return Promise.resolve({ error: 'runtime not ready' });
  const id = ++seq;
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      waiting.delete(id);
      resolve({ error: `over ${budgetMs} ms budget` });
    }, budgetMs);
    waiting.set(id, (r) => {
      clearTimeout(t);
      resolve(r);
    });
    child!.stdin!.write(`${JSON.stringify({ id, text: text.slice(-4000) })}\n`);
  });
}

const band = (s: number, [e, h]: [number, number]) => (s >= h ? 'high' : s >= e ? 'elevated' : 'low');

// DET-INJ on new text only (RB-DET-05). `where` picks the threshold table.
export async function detectInjection(text: string, tier: Tier, where: 'prompt' | 'tool'): Promise<DetectorResult & { ms?: number; reason?: string; within_da_budget?: boolean }> {
  const cfg = state.detectors.get('DET-INJ');
  const base = { id: 'DET-INJ', version: cfg?.version ?? 'unknown' };
  if (!cfg || cfg.mode === 'off') return { ...base, status: 'unavailable', reason: 'off' };
  if (!text.trim()) return { ...base, status: cfg.mode === 'active' ? 'ok' : 'shadow', score: 0, band: 'low' };
  const r = await score(text, CAP_MS);
  if (r.error || r.score === undefined) return { ...base, status: 'unavailable', reason: r.error ?? 'no score', ms: r.ms };
  return { ...base, status: cfg.mode === 'active' ? 'ok' : 'shadow', score: Math.round(r.score * 1000) / 1000, band: band(r.score, (where === 'prompt' ? INJ_PROMPT : INJ_TOOL)[tier]), ms: r.ms, within_da_budget: (r.ms ?? 0) <= DA_BUDGET_MS };
}

// Detectors with no model yet always report unavailable.
export function notDeployed(): DetectorResult[] {
  return ['DET-JB', 'DET-PII'].map((id) => ({ id, version: state.detectors.get(id)?.version ?? 'not-deployed', status: 'unavailable' as const }));
}
