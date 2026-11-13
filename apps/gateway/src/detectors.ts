import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { INJ_THRESHOLDS, MODEL_DETECTORS, REPO_ROOT, type DetectorResult, type Tier } from '@signet/core';
import { pinCheck, setRunningHash } from './pins';
import * as state from './state';

// Detector runtime (DA 3, E38). Each model detector (DET-INJ, DET-JB) runs in its own separate, stateless
// process: it gets text and returns a score, with no tools, no memory between calls and no instruction
// channel (DA 6 mechanism 5). Each process starts under Node's permission model with read-only access to
// its own model files. Network isolation is enforced by the deployment (Kubernetes NetworkPolicy); the
// worker has no network code. A detector that is off, warming up, or over its latency budget reports
// unavailable (RB-INV-06, RB-LAT-07). Shadow detectors score and log but never change a decision (RB-MOD-03).
//
// Models are installed by scripts/fetch-models.mjs from pinned Hugging Face revisions (hash-checked).
// The mmBERT-small models take about 60-80 ms on a 4-core CPU, over the DA 3 budget of 15 ms, so the
// gateway never waits for them inline: tool responses are scored right after they return, and prompts are
// scored while the cloud LLM call is in flight. A result that has not arrived within this cap counts as
// unavailable. A GPU pool (RB-LAT-05) restores the inline path.

type ModelId = 'DET-INJ' | 'DET-JB';
const DA_BUDGET_MS = 15; // DA 3 p95 budget for DET-INJ and DET-JB
const CAP_MS = Number(process.env.SIGNET_DET_INJ_CAP_MS ?? 3000);
const INJ_PROMPT = INJ_THRESHOLDS.prompt;
const INJ_TOOL = INJ_THRESHOLDS.tool;
// DET-JB starts with the DET-INJ prompt thresholds ("same family, separate head", DA 3).
const JB = INJ_THRESHOLDS.prompt;

interface Runtime { child: ChildProcess | null; ready: boolean; seq: number; waiting: Map<number, (r: { score?: number; ms?: number; error?: string }) => void>; info: string }
const runtimes = new Map<ModelId, Runtime>();
export let modelInfo = 'not loaded';
let isolationInfo: Record<string, unknown> = { runtime: 'not started' };
/** How the detector runtime is isolated (DA 6 mechanism 5, SGC-SELF-008), reported in the heartbeat. */
export const isolation = () => isolationInfo;
const refreshInfo = () => { modelInfo = [...runtimes].map(([id, r]) => `${id}: ${r.info}`).join('; ') || 'not loaded'; };

export const modelDir = (id: ModelId) => join(process.env.SIGNET_MODELS_DIR ?? join(REPO_ROOT, 'models'), MODEL_DETECTORS[id].folder);

function startOne(id: ModelId) {
  const dir = modelDir(id);
  const rt: Runtime = { child: null, ready: false, seq: 0, waiting: new Map(), info: 'starting' };
  runtimes.set(id, rt);
  if (!existsSync(join(dir, 'onnx'))) {
    rt.info = `no model files in ${dir} (run scripts/fetch-models.mjs)`;
    return;
  }
  const worker = join(dirname(fileURLToPath(import.meta.url)), 'detector-worker.mjs');
  const nm = join(REPO_ROOT, 'node_modules');
  isolationInfo = { runtime: 'separate process', processes: [...runtimes.keys()], node_permission_model: true, fs_read: ['own model files', 'node_modules', 'worker script'], fs_write: false, child_processes: false, env_vars: ['PATH', 'SYSTEMROOT'], native_addons: 'ONNX runtime only', network: 'no network code; egress is blocked by the deployment (Kubernetes NetworkPolicy)', tools: false, state_between_calls: false };
  const child = spawn(process.execPath, ['--permission', `--allow-fs-read=${dir}`, `--allow-fs-read=${nm}`, `--allow-fs-read=${worker}`, '--allow-addons', worker, dir], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: { PATH: process.env.PATH ?? '', SYSTEMROOT: process.env.SYSTEMROOT ?? '' }, // no secrets in the detector's environment
  });
  rt.child = child;
  let buf = '';
  child.stdout!.on('data', (d: Buffer) => {
    buf += d.toString();
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      const msg = JSON.parse(line) as { id?: number; ready?: boolean; info?: string; sha256?: string; score?: number; ms?: number; error?: string };
      if (msg.ready) {
        rt.ready = true;
        if (msg.sha256) setRunningHash(id, msg.sha256);
        rt.info = msg.info ?? 'ready';
        refreshInfo();
        console.log(`[gateway] ${id} runtime ready: ${rt.info}`);
      } else if (msg.id !== undefined) {
        rt.waiting.get(msg.id)?.(msg);
        rt.waiting.delete(msg.id);
      }
    }
  });
  child.on('exit', (code) => {
    rt.ready = false;
    rt.info = `runtime exited (${code})`;
    refreshInfo();
    for (const fn of rt.waiting.values()) fn({ error: 'runtime exited' });
    rt.waiting.clear();
  });
}

export function startRuntime() {
  if (process.env.SIGNET_DET_RUNTIME === 'off') {
    modelInfo = 'disabled on this node (SIGNET_DET_RUNTIME=off)';
    return;
  }
  for (const id of Object.keys(MODEL_DETECTORS) as ModelId[]) startOne(id);
  refreshInfo();
}

/** Stop the detector processes (shutdown and tests). */
export function stopRuntime() {
  for (const rt of runtimes.values()) rt.child?.kill();
  runtimes.clear();
  refreshInfo();
}

function score(id: ModelId, text: string, budgetMs: number): Promise<{ score?: number; ms?: number; error?: string }> {
  const rt = runtimes.get(id);
  if (!rt?.child || !rt.ready) return Promise.resolve({ error: 'runtime not ready' });
  const n = ++rt.seq;
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      rt.waiting.delete(n);
      resolve({ error: `over ${budgetMs} ms budget` });
    }, budgetMs);
    rt.waiting.set(n, (r) => {
      clearTimeout(t);
      resolve(r);
    });
    rt.child!.stdin!.write(`${JSON.stringify({ id: n, text: text.slice(-4000) })}\n`);
  });
}

const band = (s: number, [e, h]: readonly [number, number]) => (s >= h ? 'high' : s >= e ? 'elevated' : 'low');
export type ModelResult = DetectorResult & { ms?: number; reason?: string; within_da_budget?: boolean };

async function detect(id: ModelId, text: string, thresholds: readonly [number, number]): Promise<ModelResult> {
  const cfg = state.detectors.get(id);
  const pin = pinCheck(id);
  const base = { id, version: cfg?.version ?? 'unknown', ...(pin.sha256 ? { sha256: pin.sha256 } : {}), thresholds };
  if (!cfg || cfg.mode === 'off' || cfg.version === 'not-deployed') return { ...base, status: 'unavailable', reason: 'off' };
  if (!pin.ok) return { ...base, status: 'unavailable', reason: `pin mismatch: ${pin.reason}` };
  const scored = cfg.mode === 'active' ? 'ok' : 'shadow';
  if (!text.trim()) return { ...base, status: scored, score: 0, band: 'low' };
  // An instruction needs words. Identifiers, numbers and status codes ("C-1", "delivered") cannot
  // carry one, and the classifiers are unreliable on them, so they are not scored.
  if ((text.match(/\p{L}{2,}/gu)?.length ?? 0) < 3) return { ...base, status: scored, score: 0, band: 'low', reason: 'fewer than 3 words' };
  const r = await score(id, text, CAP_MS);
  if (r.error || r.score === undefined) return { ...base, status: 'unavailable', reason: r.error ?? 'no score', ms: r.ms };
  return { ...base, status: scored, score: Math.round(r.score * 1000) / 1000, band: band(r.score, thresholds), ms: r.ms, within_da_budget: (r.ms ?? 0) <= DA_BUDGET_MS };
}

// DET-INJ on new text only (RB-DET-05). `where` picks the threshold table.
export const detectInjection = (text: string, tier: Tier, where: 'prompt' | 'tool') => detect('DET-INJ', text, (where === 'prompt' ? INJ_PROMPT : INJ_TOOL)[tier]);

// DET-JB on the new user text (DA 3: block response, step-up).
export const detectJailbreak = (text: string, tier: Tier) => detect('DET-JB', text, JB[tier]);

// Detectors with no model yet always report unavailable.
export function notDeployed(): DetectorResult[] {
  return ['DET-JB', 'DET-PII']
    .filter((id) => (state.detectors.get(id)?.version ?? 'not-deployed') === 'not-deployed')
    .map((id) => ({ id, version: 'not-deployed', status: 'unavailable' as const }));
}
