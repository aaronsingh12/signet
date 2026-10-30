import { maskCard, rewrite, scan, type CatalogueModel, type CompiledAction, type CompiledPolicy, type DataTag } from '@signet/core';

// Data-class matrix (Rulebook v0.2). Every prompt goes to the cloud LLM, which is always treated as
// outside the tenant boundary (D-19). A seal can only tighten these defaults.

export type DataAction = 'allow' | 'log_only' | 'tokenise' | 'block' | 'require_approval';

export interface TagDecision {
  action: DataAction;
  exfiltration: boolean; // Restricted tag to a destination the seal does not allow (RB-KILL-02)
  rule: string;
}

const RESTRICTED = new Set<DataTag>(['secrets', 'payment_card', 'special_category', 'legal_privileged']);

// Prompt column.
export function promptDecision(tag: DataTag, policy: Pick<CompiledPolicy, 'prompt_tags' | 'forbidden_tags'>, model: CatalogueModel): TagDecision {
  const allowed = policy.prompt_tags.includes(tag);
  if (tag === 'secrets') return { action: 'block', exfiltration: true, rule: 'RB-INV-16' };
  if (policy.forbidden_tags.includes(tag)) return { action: 'block', exfiltration: RESTRICTED.has(tag), rule: RESTRICTED.has(tag) ? 'RB-KILL-02' : 'RB-DATA-matrix' };
  switch (tag) {
    case 'payment_card':
    case 'special_category':
      return allowed ? { action: 'tokenise', exfiltration: false, rule: 'RB-DATA-matrix' } : { action: 'block', exfiltration: true, rule: 'RB-KILL-02' };
    case 'legal_privileged':
      return { action: 'block', exfiltration: !allowed, rule: allowed ? 'RB-DATA-matrix' : 'RB-KILL-02' };
    case 'financial_account':
    case 'personal':
      // In clear only when RB-DATA-01/-02 are met; the provider terms record is not verified yet.
      return { action: 'tokenise', exfiltration: false, rule: 'RB-DATA-01' };
    case 'source_code':
      return { action: model.code_approved ? 'allow' : 'log_only', exfiltration: false, rule: 'RB-DATA-matrix' };
    case 'confidential_doc':
      return { action: allowed ? 'allow' : 'block', exfiltration: false, rule: 'RB-DATA-matrix' };
  }
}

// Tool-arguments column: tools receive only the tags in their data scope.
export function toolArgDecision(tag: DataTag, action: CompiledAction | undefined, policy: Pick<CompiledPolicy, 'forbidden_tags'>): TagDecision {
  const scoped = action?.data_scopes.includes(tag) ?? false;
  if (tag === 'secrets') return { action: 'block', exfiltration: true, rule: 'RB-INV-16' }; // the gateway injects real credentials itself
  if (policy.forbidden_tags.includes(tag) && !scoped) return { action: 'block', exfiltration: RESTRICTED.has(tag), rule: RESTRICTED.has(tag) ? 'RB-KILL-02' : 'RB-DATA-matrix' };
  switch (tag) {
    case 'payment_card':
    case 'special_category':
      return scoped ? { action: 'allow', exfiltration: false, rule: 'RB-DATA-matrix' } : { action: 'block', exfiltration: true, rule: 'RB-KILL-02' };
    case 'legal_privileged':
      return { action: 'require_approval', exfiltration: false, rule: 'RB-DATA-matrix' };
    case 'financial_account':
    case 'personal':
    case 'confidential_doc':
      return scoped ? { action: 'allow', exfiltration: false, rule: 'RB-DATA-matrix' } : { action: 'block', exfiltration: false, rule: 'RB-DATA-matrix' };
    case 'source_code':
      return { action: 'allow', exfiltration: false, rule: 'RB-DATA-matrix' };
  }
}

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

export function inspectPrompt(messages: Msg[], policy: CompiledPolicy, model: CatalogueModel, tokenise: (value: string, tag: DataTag) => string): Inspection {
  const events: DlpEvent[] = [];
  let blocked: Inspection['blocked'] = null;
  let exfiltration: Inspection['exfiltration'] = null;
  let tokenised = 0;
  const out = messages.map((m) =>
    mapMessage(m, (text) =>
      rewrite(text, scan(text), (f) => {
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

export interface ArgInspection {
  events: DlpEvent[];
  blocked: { tag: DataTag; rule: string } | null;
  exfiltration: { tag: DataTag; recogniser: string; rule: string } | null;
  approval: { tag: DataTag; rule: string } | null;
}

export function inspectArgs(args: unknown, action: CompiledAction | undefined, policy: CompiledPolicy): ArgInspection {
  const events: DlpEvent[] = [];
  const out: ArgInspection = { events, blocked: null, exfiltration: null, approval: null };
  const walk = (v: unknown) => {
    if (typeof v === 'string') {
      for (const f of scan(v)) {
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

export function stringsOf(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(stringsOf).join('\n');
  if (value && typeof value === 'object') return Object.values(value).map(stringsOf).join('\n');
  return '';
}
