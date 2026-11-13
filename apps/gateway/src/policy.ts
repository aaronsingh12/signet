import { maskCard, promptDecision, rewrite, scan, toolArgDecision, type CatalogueModel, type CompiledAction, type CompiledPolicy, type DataTag, type Finding } from '@signet/core';

export { promptDecision, toolArgDecision };

export interface DlpEvent {
  direction: 'in' | 'out';
  tag: DataTag;
  recogniser: string;
  action: string;
}

type Msg = { role: string; content?: unknown; tool_calls?: { function?: { arguments?: string } }[]; [k: string]: unknown };

function mapText(content: unknown, fn: (s: string) => string): unknown {
  if (typeof content === 'string') return fn(content);
  if (Array.isArray(content)) {
    return content.map((p) => (p && typeof p === 'object' && typeof (p as { text?: unknown }).text === 'string' ? { ...p, text: fn((p as { text: string }).text) } : p));
  }
  return content;
}

function mapMessage<T extends Msg>(m: T, fn: (s: string) => string): T {
  const out: T = { ...m, content: mapText(m.content, fn) };
  if (Array.isArray(m.tool_calls)) {
    out.tool_calls = m.tool_calls.map((tc) => (tc.function && typeof tc.function.arguments === 'string' ? { ...tc, function: { ...tc.function, arguments: fn(tc.function.arguments) } } : tc));
  }
  return out;
}

/** Every text segment of the messages, as inspectPrompt sees them (for detectors that score segments). */
export function textsOf(messages: Msg[]): string[] {
  const parts: string[] = [];
  for (const m of messages) mapMessage(m, (s) => (parts.push(s), s));
  return parts;
}

export function textOf(messages: Msg[]): string {
  const parts: string[] = [];
  for (const m of messages) mapMessage(m, (s) => (parts.push(s), s));
  return parts.join('\n');
}

// New text in this turn (RB-DET-05): the last user message and any tool results after it.
export function newTextOf(messages: Msg[]): { user: string; tool: string } {
  let i = messages.length - 1;
  const tool: string[] = [];
  while (i >= 0 && messages[i]!.role === 'tool') tool.unshift(textOf([messages[i--]!]));
  const lastUser = [...messages].reverse().find((m) => m.role === 'user');
  return { user: lastUser ? textOf([lastUser]) : '', tool: tool.join('\n') };
}

export interface Inspection {
  messages: Msg[];
  events: DlpEvent[];
  blocked: { tag: DataTag; rule: string } | null;
  exfiltration: { tag: DataTag; recogniser: string; rule: string } | null;
  tokenised: number;
}

// `extra` holds findings from an active detector (DET-PII) per text segment. Pattern findings win where
// both cover the same characters; detector findings only add to them.
export function inspectPrompt(messages: Msg[], policy: CompiledPolicy, model: CatalogueModel, tokenise: (value: string, tag: DataTag) => string, extra?: Map<string, Finding[]>): Inspection {
  const events: DlpEvent[] = [];
  let blocked: Inspection['blocked'] = null;
  let exfiltration: Inspection['exfiltration'] = null;
  let tokenised = 0;
  const out = messages.map((m) =>
    mapMessage(m, (text) =>
      rewrite(text, withExtra(scan(text), extra?.get(text)), (f) => {
        const d = promptDecision(f.tag, policy, model);
        events.push({ direction: 'in', tag: f.tag, recogniser: f.recogniser, action: d.action });
        if (d.action === 'block') {
          blocked ??= { tag: f.tag, rule: d.rule };
          if (d.exfiltration) exfiltration ??= { tag: f.tag, recogniser: f.recogniser, rule: d.rule };
          return f.value;
        }
        if (d.action === 'tokenise') {
          tokenised++;
          return tokenise(f.value, f.tag);
        }
        return f.value;
      }),
    ),
  );
  return { messages: out, events, blocked, exfiltration, tokenised };
}

function withExtra(found: Finding[], extra: Finding[] | undefined): Finding[] {
  if (!extra?.length) return found;
  const out = [...found];
  for (const e of extra) if (!out.some((o) => e.start < o.end && o.start < e.end)) out.push(e);
  return out.sort((a, b) => a.start - b.start);
}

export interface ArgInspection {
  events: DlpEvent[];
  blocked: { tag: DataTag; rule: string } | null;
  exfiltration: { tag: DataTag; recogniser: string; rule: string } | null;
  approval: { tag: DataTag; rule: string } | null;
}

/** Every string value inside tool arguments, exactly as inspectArgs sees it (for DET-PII). */
export function argStrings(args: unknown): string[] {
  const out = new Set<string>();
  const walk = (v: unknown) => {
    if (typeof v === 'string') { if (v.trim()) out.add(v); } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(args);
  return [...out];
}

// `extra`: findings from an active DET-PII per string, added where no pattern finding overlaps them.
export function inspectArgs(args: unknown, action: CompiledAction | undefined, policy: CompiledPolicy, extra?: Map<string, Finding[]>): ArgInspection {
  const events: DlpEvent[] = [];
  const out: ArgInspection = { events, blocked: null, exfiltration: null, approval: null };
  const walk = (v: unknown) => {
    if (typeof v === 'string') {
      for (const f of withExtra(scan(v), extra?.get(v))) {
        const d = toolArgDecision(f.tag, action, policy);
        events.push({ direction: 'in', tag: f.tag, recogniser: f.recogniser, action: d.action });
        if (d.action === 'block') {
          out.blocked ??= { tag: f.tag, rule: d.rule };
          if (d.exfiltration) out.exfiltration ??= { tag: f.tag, recogniser: f.recogniser, rule: d.rule };
        }
        if (d.action === 'require_approval') out.approval ??= { tag: f.tag, rule: d.rule };
      }
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(args);
  return out;
}

// Response column: secrets are always redacted (RB-BL-10), card numbers masked to the last four
// digits; tokens are restored only for the calling agent and session.
export function cleanResponseText(text: string, detokenise: (s: string) => string, events: DlpEvent[]): string {
  const restored = detokenise(text);
  return rewrite(restored, scan(restored), (f) => {
    if (f.tag === 'secrets') {
      events.push({ direction: 'out', tag: f.tag, recogniser: f.recogniser, action: 'redact' });
      return '[REDACTED:secret]';
    }
    if (f.tag === 'payment_card') {
      events.push({ direction: 'out', tag: f.tag, recogniser: f.recogniser, action: 'mask' });
      return maskCard(f.value);
    }
    events.push({ direction: 'out', tag: f.tag, recogniser: f.recogniser, action: 'allow' });
    return f.value;
  });
}

// Applies cleanResponseText to every string inside a JSON value (tool results).
export function cleanJson<T>(value: T, events: DlpEvent[]): T {
  if (typeof value === 'string') return cleanResponseText(value, (s) => s, events) as T;
  if (Array.isArray(value)) return value.map((v) => cleanJson(v, events)) as T;
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, cleanJson(v, events)])) as T;
  return value;
}

// The text values inside a tool result, each once. JSON carried as a string (MCP text content
// repeats structuredContent that way) is opened up, so field names are never scored as text.
export function stringsOf(value: unknown): string {
  const out = new Set<string>();
  const walk = (v: unknown) => {
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^[[{]/.test(s)) {
        try {
          return walk(JSON.parse(s));
        } catch {
          /* not JSON: plain text */
        }
      }
      if (s) out.add(s);
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if (o.type === 'text' && typeof o.text === 'string') return walk(o.text); // MCP content block
      Object.values(o).forEach(walk);
    }
  };
  walk(value);
  return [...out].join('\n');
}
