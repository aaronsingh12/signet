import { randomBytes } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';

// OpenTelemetry (BP 2 principle 8, 5.2 step 14, 8.5): W3C trace context and an OTLP/HTTP exporter.
// Every gateway decision becomes one span with the OpenTelemetry GenAI semantic conventions plus Signet's
// decision attributes, so any observability stack (Datadog, Grafana, New Relic, Dynatrace, Jaeger ...)
// sees governed agent calls next to the agents' own traces. Prompts, answers and arguments are never
// exported: only metadata that is already in the ledger record.
//
// Standard OpenTelemetry settings:
//   OTEL_EXPORTER_OTLP_ENDPOINT          for example http://localhost:4318 (traces go to <endpoint>/v1/traces)
//   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT   full traces URL, overrides the above
//   OTEL_EXPORTER_OTLP_HEADERS           "key=value,key2=value2" (for example an API key header)
//   OTEL_SERVICE_NAME                    default signet-gateway

export interface TraceContext { traceId: string; spanId: string; parentSpanId: string | null; sampled: boolean }

const hex = (n: number) => randomBytes(n).toString('hex');
const ZERO = /^0+$/;

/** Follow the caller's W3C traceparent when it is valid; otherwise start a new trace. */
export function traceFrom(headers: IncomingHttpHeaders): TraceContext {
  const raw = typeof headers.traceparent === 'string' ? headers.traceparent.trim().toLowerCase() : '';
  const m = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/.exec(raw);
  if (m && m[1] !== 'ff' && !ZERO.test(m[2]!) && !ZERO.test(m[3]!)) return { traceId: m[2]!, spanId: hex(8), parentSpanId: m[3]!, sampled: (parseInt(m[4]!, 16) & 1) === 1 };
  return { traceId: hex(16), spanId: hex(8), parentSpanId: null, sampled: true };
}

export const traceparentOf = (t: TraceContext) => `00-${t.traceId}-${t.spanId}-${t.sampled ? '01' : '00'}`;

type AttrValue = string | number | boolean | string[];
interface SpanInput {
  trace: TraceContext;
  name: string;
  startMs: number;
  endMs: number;
  error: string | null;
  attributes: Record<string, AttrValue | null | undefined>;
}

const attr = (key: string, v: AttrValue) => ({
  key,
  value: Array.isArray(v) ? { arrayValue: { values: v.map((s) => ({ stringValue: s })) } }
    : typeof v === 'boolean' ? { boolValue: v }
      : typeof v === 'number' ? (Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v })
        : { stringValue: v },
});
const nanos = (ms: number) => (BigInt(Math.round(ms * 1000)) * 1000n).toString();

export function toOtlpSpan(s: SpanInput) {
  return {
    traceId: s.trace.traceId,
    spanId: s.trace.spanId,
    ...(s.trace.parentSpanId ? { parentSpanId: s.trace.parentSpanId } : {}),
    name: s.name,
    kind: 2, // SERVER: the agent called the gateway
    startTimeUnixNano: nanos(s.startMs),
    endTimeUnixNano: nanos(s.endMs),
    attributes: Object.entries(s.attributes).filter(([, v]) => v !== null && v !== undefined && !(Array.isArray(v) && !v.length)).map(([k, v]) => attr(k, v as AttrValue)),
    status: s.error ? { code: 2, message: s.error } : { code: 1 },
  };
}

// --- Exporter: batched, best effort, never blocks or fails a request ---------------------------------

export function otlpTarget(env = process.env): { url: string; headers: Record<string, string> } | null {
  const url = env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT?.trim() || (env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim() ? `${env.OTEL_EXPORTER_OTLP_ENDPOINT.trim().replace(/\/$/, '')}/v1/traces` : '');
  if (!url) return null;
  const headers: Record<string, string> = {};
  for (const pair of (env.OTEL_EXPORTER_OTLP_HEADERS ?? '').split(',')) {
    const i = pair.indexOf('=');
    if (i > 0) headers[decodeURIComponent(pair.slice(0, i).trim()).toLowerCase()] = decodeURIComponent(pair.slice(i + 1).trim());
  }
  return { url, headers };
}

const queue: ReturnType<typeof toOtlpSpan>[] = [];
const MAX_QUEUE = 5000;
let timer: NodeJS.Timeout | null = null;
export const stats = { exported: 0, dropped: 0, failed_batches: 0 };

export function exportSpan(s: SpanInput) {
  if (!s.trace.sampled || !otlpTarget()) return;
  if (queue.length >= MAX_QUEUE) { stats.dropped++; return; }
  queue.push(toOtlpSpan(s));
  if (queue.length >= 100) void flush();
  else if (!timer) timer = setTimeout(() => void flush(), 2000).unref();
}

export async function flush(): Promise<void> {
  if (timer) { clearTimeout(timer); timer = null; }
  const target = otlpTarget();
  if (!target || !queue.length) return;
  const batch = queue.splice(0, 500);
  const body = {
    resourceSpans: [{
      resource: { attributes: [attr('service.name', process.env.OTEL_SERVICE_NAME ?? 'signet-gateway'), attr('service.namespace', 'signet'), ...(process.env.SIGNET_NODE_ID ? [attr('service.instance.id', process.env.SIGNET_NODE_ID)] : [])] },
      scopeSpans: [{ scope: { name: 'signet.gateway' }, spans: batch }],
    }],
  };
  try {
    const r = await fetch(target.url, { method: 'POST', headers: { 'content-type': 'application/json', ...target.headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error(`collector answered ${r.status}`);
    stats.exported += batch.length;
  } catch (e) {
    stats.failed_batches++;
    stats.dropped += batch.length;
    console.error(`[gateway] OpenTelemetry export failed, ${batch.length} span(s) dropped: ${(e as Error).message}`);
  }
  if (queue.length) timer = setTimeout(() => void flush(), 2000).unref();
}
