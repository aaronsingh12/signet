// Detector process (E38). Reads {id, text} lines on stdin, writes {id, score, ms} lines on stdout.
// Stateless: nothing is kept between calls. No network code, no tools, no instruction channel.
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { createReadStream, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';

const modelDir = process.argv[2];
const { AutoTokenizer, AutoModelForSequenceClassification, env } = await import('@huggingface/transformers');
env.allowRemoteModels = false;
env.allowLocalModels = true;
env.localModelPath = join(modelDir, '..');
const name = modelDir.split(/[\\/]/).pop();
const quantized = process.argv[3] !== 'fp32' && existsSync(join(modelDir, 'onnx', 'model_quantized.onnx'));
const tokenizer = await AutoTokenizer.from_pretrained(name);
const model = await AutoModelForSequenceClassification.from_pretrained(name, { dtype: quantized ? 'q8' : 'fp32' });
// The class to score: injection, jailbreak or malicious, whatever the model calls it.
const injIndex = Number(Object.entries(model.config.id2label).find(([, l]) => /inject|jailbreak|malicious/i.test(l))?.[0] ?? 1);

const softmax = (xs) => {
  const m = Math.max(...xs);
  const e = xs.map((x) => Math.exp(x - m));
  const s = e.reduce((a, b) => a + b, 0);
  return e.map((x) => x / s);
};

async function scoreText(text) {
  const inputs = await tokenizer(text, { truncation: true, max_length: 512 });
  const { logits } = await model(inputs);
  return softmax(Array.from(logits.data))[injIndex];
}

await scoreText('warm up'); // first run compiles the graph
// The hash of the weights actually loaded, checked against the pin in the policy bundle (DA 3). A model
// whose weights sit in a separate .onnx.data file is hashed over both files, graph first.
const file = join(modelDir, 'onnx', quantized ? 'model_quantized.onnx' : 'model.onnx');
const h = createHash('sha256');
for (const f of [file, `${file}.data`].filter((f) => existsSync(f))) {
  await new Promise((resolve, reject) => createReadStream(f).on('data', (d) => h.update(d)).on('end', resolve).on('error', reject));
}
const sha256 = h.digest('hex');
process.stdout.write(`${JSON.stringify({ ready: true, info: `${name} ${quantized ? 'int8' : 'fp32'}`, sha256 })}\n`);

for await (const line of createInterface({ input: process.stdin })) {
  let msg;
  try {
    msg = JSON.parse(line);
    const t0 = performance.now();
    const score = await scoreText(String(msg.text ?? ''));
    process.stdout.write(`${JSON.stringify({ id: msg.id, score, ms: Math.round(performance.now() - t0) })}\n`);
  } catch (e) {
    process.stdout.write(`${JSON.stringify({ id: msg?.id, error: String(e?.message ?? e) })}\n`);
  }
}
