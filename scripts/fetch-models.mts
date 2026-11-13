// Install the model detectors (DET-INJ, DET-JB) from their pinned Hugging Face revisions and check each
// model against the sha256 Signet pins (DA 3 "pinned and hashed"). A model that does not match is deleted
// and the script fails, so a gateway never runs weights that were not benchmarked.
//   npx tsx scripts/fetch-models.mts [--dir <models dir>]
import { createHash } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { MODEL_DETECTORS, REPO_ROOT } from '@signet/core';

const i = process.argv.indexOf('--dir');
const root = i > 0 ? process.argv[i + 1]! : process.env.SIGNET_MODELS_DIR ?? join(REPO_ROOT, 'models');

async function weightsHash(dir: string): Promise<string | null> {
  const files = ['onnx/model.onnx', 'onnx/model.onnx.data'].map((f) => join(dir, f)).filter((f) => existsSync(f));
  if (!files.length) return null;
  const h = createHash('sha256');
  for (const f of files) await new Promise<void>((res, rej) => createReadStream(f).on('data', (d) => h.update(d)).on('end', () => res()).on('error', rej));
  return h.digest('hex');
}

let failed = false;
for (const [id, m] of Object.entries(MODEL_DETECTORS)) {
  const dir = join(root, m.folder);
  const files = m.files.map((f) => { const [from, to] = f.split('=>').map((s) => s.trim()); return { from: from!, to: to ?? from! }; });
  if ((await weightsHash(dir)) === m.sha256 && files.every((f) => existsSync(join(dir, f.to)))) {
    console.log(`${id}: ${m.repo}@${m.revision.slice(0, 7)} already installed in ${dir}`);
    continue;
  }
  console.log(`${id}: downloading ${m.repo}@${m.revision.slice(0, 7)} (${m.licence})`);
  for (const f of files) {
    const url = `https://huggingface.co/${m.repo}/resolve/${m.revision}/${f.from}`;
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    const out = join(dir, f.to);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, Buffer.from(await r.arrayBuffer()));
  }
  const got = await weightsHash(dir);
  if (got !== m.sha256) {
    console.error(`${id}: weights hash ${got} does not match the pin ${m.sha256}; deleted`);
    rmSync(dir, { recursive: true, force: true });
    failed = true;
  } else console.log(`${id}: installed, sha256 ${got.slice(0, 16)}… matches the pin`);
}
process.exit(failed ? 1 : 0);
