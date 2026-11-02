import { startStack } from './harness';

// npm run test:e2e [-- suite ...]
// Each suite gets a fresh, isolated stack. Suites: connectivity (scenarios 1-7 of the connectivity
// work), gate-phase1, gate-phase2. Needs Keycloak (npm run up) and the configured cloud LLM.

const SUITES: Record<string, () => Promise<{ run: () => Promise<unknown> }>> = {
  connectivity: () => import('./connectivity'),
  'gate-phase1': () => import('./gate-phase1'),
  'gate-phase2': () => import('./gate-phase2'),
};

const wanted = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const names = wanted.length ? wanted : Object.keys(SUITES);
const results: { suite: string; ok: boolean; ms: number; error?: string }[] = [];

for (const name of names) {
  const load = SUITES[name];
  if (!load) {
    console.error(`unknown suite ${name}; choose from ${Object.keys(SUITES).join(', ')}`);
    process.exit(2);
  }
  console.log(`\n\x1b[1m=== ${name} ===\x1b[0m`);
  const t0 = Date.now();
  let stack;
  try {
    stack = await startStack(name);
    const mod = await load();
    await mod.run();
    results.push({ suite: name, ok: true, ms: Date.now() - t0 });
    await stack.stop();
  } catch (e) {
    console.error(`\x1b[31m${name} FAILED: ${(e as Error).stack ?? e}\x1b[0m`);
    results.push({ suite: name, ok: false, ms: Date.now() - t0, error: (e as Error).message });
    await stack?.stop(true);
  }
}

console.log('\n=== e2e results ===');
for (const r of results) console.log(`${r.ok ? '\x1b[32mPASS' : '\x1b[31mFAIL'}\x1b[0m  ${r.suite.padEnd(14)} ${(r.ms / 1000).toFixed(1)} s${r.error ? `  ${r.error}` : ''}`);
process.exit(results.every((r) => r.ok) ? 0 : 1);
