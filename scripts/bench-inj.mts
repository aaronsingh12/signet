// Benchmark DET-INJ with the real model (DA 6 mechanism 4). Runs the gateway's detector worker on the
// fixed set and, with --record, writes the result to the control plane database as the release record.
//   npx tsx scripts/bench-inj.mts [--record]      (needs models/deberta-injection and DATABASE_URL for --record)
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { BENCHMARK_SETS, INJ_THRESHOLDS, REPO_ROOT, meetsTargets, metrics } from '@signet/core';

const dir = join(REPO_ROOT, 'models', 'deberta-injection');
const worker = join(REPO_ROOT, 'apps', 'gateway', 'src', 'detector-worker.mjs');
const child = spawn(process.execPath, ['--permission', `--allow-fs-read=${dir}`, `--allow-fs-read=${join(REPO_ROOT, 'node_modules')}`, `--allow-fs-read=${worker}`, '--allow-addons', worker, dir], { stdio: ['pipe', 'pipe', 'inherit'] });
const lines = createInterface({ input: child.stdout! })[Symbol.asyncIterator]();
const next = async () => JSON.parse(String((await lines.next()).value)) as { ready?: boolean; sha256?: string; info?: string; score?: number; error?: string };
const ready = await next();
if (!ready.ready) throw new Error('detector worker did not start');
const cases = BENCHMARK_SETS['DET-INJ'].cases;
const rows: { label: 0 | 1; lang: string; predicted: boolean | null; score?: number; text: string }[] = [];
for (const [i, c] of cases.entries()) {
  child.stdin!.write(`${JSON.stringify({ id: i, text: c.text })}\n`);
  const r = await next();
  const t = INJ_THRESHOLDS[c.where ?? 'prompt'].T2;
  rows.push({ label: c.label, lang: c.lang, predicted: r.score === undefined ? null : r.score >= t[0], score: r.score, text: c.text });
}
child.kill();
const m = metrics(rows);
const gate = meetsTargets('DET-INJ', m);
for (const r of rows) if (r.predicted !== (r.label === 1)) console.log(`${r.label ? 'MISSED ' : 'FALSE+ '} ${r.score?.toFixed(3)} [${r.lang}] ${r.text.slice(0, 90)}`);
console.log(JSON.stringify({ model: ready.info, sha256: ready.sha256, ...m, gate }, null, 1));
if (process.argv.includes('--record')) {
  const bench = await import('../apps/control/src/benchmarks');
  const rec = await bench.record({ detector: 'DET-INJ', version: 'deberta-v3-base-injection-v2-fp32', sha256: ready.sha256!, metrics: m, ran_by: process.env.USERNAME ?? 'cli', runner: 'scripts/bench-inj.mts' });
  console.log('recorded', rec.id, rec.passed ? 'PASSED' : 'FAILED');
  process.exit(0);
}
