// Benchmark a model detector (DET-INJ or DET-JB) with the real model (DA 6 mechanism 4). Runs the
// gateway's detector worker on the fixed set and, with --record, writes the result to the control plane
// database as the release record for that version and hash.
//   npx tsx scripts/bench-model.mts --detector DET-INJ [--model <folder under models/>] [--record]
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { BENCHMARK_SETS, INJ_THRESHOLDS, MODEL_DETECTORS, REPO_ROOT, meetsTargets, metrics } from '@signet/core';

const arg = (k: string) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : undefined; };
const detector = (arg('--detector') ?? 'DET-INJ') as 'DET-INJ' | 'DET-JB';
const release = MODEL_DETECTORS[detector];
const folder = arg('--model') ?? release.folder;
const dir = join(REPO_ROOT, 'models', folder);
const worker = join(REPO_ROOT, 'apps', 'gateway', 'src', 'detector-worker.mjs');
const child = spawn(process.execPath, ['--permission', `--allow-fs-read=${dir}`, `--allow-fs-read=${join(REPO_ROOT, 'node_modules')}`, `--allow-fs-read=${worker}`, '--allow-addons', worker, dir], { stdio: ['pipe', 'pipe', 'inherit'] });
const lines = createInterface({ input: child.stdout! })[Symbol.asyncIterator]();
const next = async () => JSON.parse(String((await lines.next()).value)) as { ready?: boolean; sha256?: string; info?: string; score?: number; ms?: number; error?: string };
const ready = await next();
if (!ready.ready) throw new Error('detector worker did not start');
const cases = BENCHMARK_SETS[detector].cases;
const rows: { label: 0 | 1; lang: string; predicted: boolean | null; score?: number; text: string }[] = [];
const ms: number[] = [];
for (const [i, c] of cases.entries()) {
  child.stdin!.write(`${JSON.stringify({ id: i, text: c.text })}\n`);
  const r = await next();
  if (r.ms !== undefined) ms.push(r.ms);
  const t = INJ_THRESHOLDS[(c as { where?: 'prompt' | 'tool' }).where ?? 'prompt'].T2;
  rows.push({ label: c.label, lang: c.lang, predicted: r.score === undefined ? null : r.score >= t[0], score: r.score, text: c.text });
}
child.kill();
ms.sort((a, b) => a - b);
const m = metrics(rows);
const gate = meetsTargets(detector, m);
for (const r of rows) if (r.predicted !== (r.label === 1)) console.log(`${r.label ? 'MISSED ' : 'FALSE+ '} ${r.score?.toFixed(3)} [${r.lang}] ${r.text.slice(0, 90)}`);
const { by_lang, ...summary } = m;
console.log(JSON.stringify({ detector, model: folder, sha256: ready.sha256, ...summary, by_lang: Object.fromEntries(Object.entries(by_lang).map(([k, v]) => [k, `${v.correct}/${v.n}`])), p50_ms: ms[Math.floor(ms.length / 2)], p95_ms: ms[Math.floor(ms.length * 0.95)], gate }));
if (process.argv.includes('--record')) {
  const version = arg('--version') ?? release.version;
  const bench = await import('../apps/control/src/benchmarks');
  const rec = await bench.record({ detector, version, sha256: ready.sha256!, metrics: m, ran_by: process.env.USERNAME ?? 'cli', runner: 'scripts/bench-model.mts' });
  console.log('recorded', rec.id, rec.passed ? 'PASSED' : 'FAILED');
  process.exit(0);
}
