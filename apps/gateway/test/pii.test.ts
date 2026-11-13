import { strict as assert } from 'node:assert';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import type { CatalogueModel, CompiledPolicy } from '@signet/core';
import { detectPii } from '../src/pii';
import { argStrings, inspectArgs, inspectPrompt } from '../src/policy';
import * as state from '../src/state';

// DET-PII (DA 3): Presidio finds names and addresses; it only masks more text, never less, and follows
// off / shadow / active / unavailable like every detector. A stand-in answers like Presidio's /analyze.
const model: CatalogueModel = { model: 'm', upstream_model: 'm', family: 'x', region: 'unverified', code_approved: true, price_per_1k_usd: { in: 0, out: 0 } };
const policy = { prompt_tags: [], forbidden_tags: [], actions: {} } as unknown as CompiledPolicy;
const text = 'Refund Priya Menon at 42 Baker Street, email priya@northwind.example';
let calls = 0;
let failing = false;
const server = createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    calls++;
    if (failing) return void res.writeHead(500).end();
    const t = JSON.parse(raw).text as string;
    const hits = [['PERSON', 'Priya Menon', 0.85], ['LOCATION', 'Baker Street', 0.85], ['PERSON', 'priya', 0.3]]
      .filter(([, v]) => t.includes(v as string)).map(([e, v, s]) => ({ entity_type: e, start: t.indexOf(v as string), end: t.indexOf(v as string) + (v as string).length, score: s }));
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(hits));
  });
});
before(async () => {
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  process.env.SIGNET_PRESIDIO_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); delete process.env.SIGNET_PRESIDIO_URL; });
const mode = (m: 'off' | 'shadow' | 'active') => state.detectors.set('DET-PII', { id: 'DET-PII', version: 'presidio-analyzer-2', mode: m } as never);

test('active: names and addresses are tokenised with the pattern findings; low scores ignored', async () => {
  mode('active');
  const pii = await detectPii([text]);
  assert.deepEqual([pii.result.status, pii.result.found], ['ok', 2]);
  let n = 0;
  const out = inspectPrompt([{ role: 'user', content: text }], policy, model, () => `<tok${++n}>`, pii.findings);
  const masked = String(out.messages[0]!.content);
  assert.match(masked, /^Refund <tok[0-9]> at 42 <tok[0-9]>, email <tok[0-9]>$/);
  assert.ok(!/Priya|Baker|northwind/.test(masked));
  assert.deepEqual(out.events.map((e) => e.recogniser).sort(), ['email', 'presidio_location', 'presidio_person']);
});

test('shadow: scored but the prompt is not changed; off: not called', async () => {
  mode('shadow');
  const pii = await detectPii([text]);
  assert.deepEqual([pii.result.status, pii.result.found], ['shadow', 2]);
  mode('off');
  const before = calls;
  const off = await detectPii([text]);
  assert.equal(off.result.status, 'unavailable');
  assert.equal(calls, before, 'an off detector is never called');
});

test('failure or missing settings: unavailable, so pattern DLP still runs and T1/T2 are held', async () => {
  mode('active');
  failing = true;
  assert.equal((await detectPii([text])).result.status, 'unavailable');
  failing = false;
  const url = process.env.SIGNET_PRESIDIO_URL;
  delete process.env.SIGNET_PRESIDIO_URL;
  assert.match((await detectPii([text])).result.reason ?? '', /SIGNET_PRESIDIO_URL/);
  process.env.SIGNET_PRESIDIO_URL = url;
});

test('tool arguments: an active DET-PII adds names and addresses; out of scope they are blocked, never a kill', async () => {
  mode('active');
  const args = { note: 'Call Priya Menon about the parcel', ref: 'C-1' };
  const pii = await detectPii(argStrings(args));
  assert.equal(pii.result.found, 1);
  const crm = { data_scopes: ['personal'] } as never;
  const shipping = { data_scopes: [] } as never;
  assert.equal(inspectArgs(args, crm, policy, pii.findings).blocked, null, 'the CRM tool may receive personal data');
  const out = inspectArgs(args, shipping, policy, pii.findings);
  assert.equal(out.blocked?.tag, 'personal');
  assert.equal(out.exfiltration, null, 'a name is blocked, not an exfiltration kill');
  assert.equal(inspectArgs(args, shipping, policy).blocked, null, 'without DET-PII the name is not seen');
});
