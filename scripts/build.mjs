// Production build: one bundled ESM file per service (BP 15: single binaries / small images).
// Native and WebAssembly packages stay external and are installed in the image.
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { execSync } from 'node:child_process';

const external = ['express', '@huggingface/transformers', 'onnxruntime-node', '@open-policy-agent/opa-wasm'];
const entries = {
  control: 'apps/control/src/index.ts',
  gateway: 'apps/gateway/src/index.ts',
  'signet-verify': 'apps/cli/src/verify.ts',
  'signet-keysweep': 'apps/cli/src/keysweep.ts',
  'mock-tools': 'apps/mock-tools/src/index.ts',
};

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });
for (const [name, entry] of Object.entries(entries)) {
  await build({
    entryPoints: [entry],
    outfile: `dist/${name}.mjs`,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    external,
    sourcemap: true,
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
    logLevel: 'warning',
  });
  console.log(`dist/${name}.mjs`);
}
cpSync('apps/gateway/src/detector-worker.mjs', 'dist/detector-worker.mjs');
cpSync('policy', 'dist/policy', { recursive: true });
execSync('npm run build -w @signet/web', { stdio: 'inherit' });
cpSync('apps/web/dist', 'dist/web', { recursive: true });
console.log('dist/web (console)');
