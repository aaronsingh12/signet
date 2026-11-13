import { strict as assert } from 'node:assert';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { exportSpan, flush, otlpTarget, stats, toOtlpSpan, traceFrom, traceparentOf } from '../src/otel';

// OpenTelemetry: W3C trace context and OTLP/HTTP export of one span per decision (metadata only).

test('trace context: follows a valid traceparent, starts a new trace otherwise', () => {
  const parent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
  const t = traceFrom({ traceparent: parent });
  assert.deepEqual([t.traceId, t.parentSpanId, t.sampled], ['4bf92f3577b34da6a3ce929d0e0e4736', '00f067aa0ba902b7', true]);
  assert.match(traceparentOf(t), /^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$/);
  for (const bad of ['00-00000000000000000000000000000000-00f067aa0ba902b7-01', 'ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', 'garbage']) {
    const n = traceFrom({ traceparent: bad });
    assert.equal(n.parentSpanId, null);
    assert.match(n.traceId, /^[0-9a-f]{32}$/);
  }
  assert.equal(traceFrom({ traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00' }).sampled, false);
});

test('settings: standard OTEL_* variables, headers parsed', () => {
  assert.equal(otlpTarget({}), null);
  assert.deepEqual(otlpTarget({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://c:4318/', OTEL_EXPORTER_OTLP_HEADERS: 'X-API-Key=abc,dd-site=eu' }), { url: 'http://c:4318/v1/traces', headers: { 'x-api-key': 'abc', 'dd-site': 'eu' } });
  assert.equal(otlpTarget({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://c', OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: 'http://t/x' })!.url, 'http://t/x');
});

test('spans: GenAI attributes, error status, empty values dropped', () => {
  const s = toOtlpSpan({ trace: traceFrom({}), name: 'chat m', startMs: 1000, endMs: 1250.5, error: 'data_blocked: no', attributes: { 'gen_ai.operation.name': 'chat', 'gen_ai.usage.input_tokens': 12, 'signet.cost_usd': 0.25, 'signet.rule_ids': ['A', 'B'], 'signet.x': null, 'signet.empty': [] } });
  assert.equal(s.startTimeUnixNano, '1000000000');
  assert.equal(s.endTimeUnixNano, '1250500000');
  assert.deepEqual(s.status, { code: 2, message: 'data_blocked: no' });
  assert.deepEqual(s.attributes.map((a) => a.key), ['gen_ai.operation.name', 'gen_ai.usage.input_tokens', 'signet.cost_usd', 'signet.rule_ids']);
  assert.deepEqual(s.attributes[1]!.value, { intValue: '12' });
});

test('exporter: batches spans to the collector with its headers; a failing collector never throws', async () => {
  const received: { headers: Record<string, unknown>; body: any }[] = [];
  let fail = false;
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => { received.push({ headers: req.headers, body: JSON.parse(raw) }); res.writeHead(fail ? 500 : 200).end('{}'); });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  Object.assign(process.env, { OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${port}`, OTEL_EXPORTER_OTLP_HEADERS: 'authorization=Bearer t' });
  try {
    const trace = traceFrom({});
    exportSpan({ trace, name: 'chat m', startMs: Date.now() - 5, endMs: Date.now(), error: null, attributes: { 'signet.decision': 'allow' } });
    exportSpan({ trace: { ...trace, sampled: false }, name: 'not sampled', startMs: 0, endMs: 1, error: null, attributes: {} });
    await flush();
    assert.equal(received.length, 1);
    assert.equal(received[0]!.headers.authorization, 'Bearer t');
    const spans = received[0]!.body.resourceSpans[0].scopeSpans[0].spans;
    assert.deepEqual(spans.map((s: { name: string }) => s.name), ['chat m'], 'unsampled spans are not exported');
    assert.equal(received[0]!.body.resourceSpans[0].resource.attributes[0].value.stringValue, 'signet-gateway');
    fail = true;
    const before = stats.failed_batches;
    exportSpan({ trace, name: 'chat m', startMs: 0, endMs: 1, error: null, attributes: {} });
    await flush();
    assert.equal(stats.failed_batches, before + 1);
  } finally {
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    delete process.env.OTEL_EXPORTER_OTLP_HEADERS;
    server.close();
  }
});
