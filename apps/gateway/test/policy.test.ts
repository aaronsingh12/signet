import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import type { CatalogueModel, CompiledAction, CompiledPolicy } from '@signet/core';
import { cleanResponseText, inspectArgs, inspectPrompt, promptDecision, toolArgDecision } from '../src/policy';

const model: CatalogueModel = { model: 'gpt-oss:120b-cloud', upstream_model: 'gpt-oss:120b', family: 'gptoss', region: 'unverified', code_approved: true, price_per_1k_usd: { in: 0, out: 0 } };

const pol = (prompt: string[] = [], forbidden: string[] = []) => ({ prompt_tags: prompt, forbidden_tags: forbidden, actions: {} }) as unknown as CompiledPolicy;
const act = (scopes: string[]) => ({ data_scopes: scopes }) as unknown as CompiledAction;

test('data-class matrix, prompt column (Rulebook v0.2)', () => {
  assert.deepEqual(promptDecision('secrets', pol(), model), { action: 'block', exfiltration: true, rule: 'RB-INV-16' });
  assert.equal(promptDecision('payment_card', pol(), model).exfiltration, true);
  assert.equal(promptDecision('payment_card', pol(['payment_card']), model).action, 'tokenise');
  assert.equal(promptDecision('legal_privileged', pol(['legal_privileged']), model).action, 'block'); // D-19: always blocked
  assert.equal(promptDecision('personal', pol(), model).action, 'tokenise');
  assert.equal(promptDecision('personal', pol([], ['personal']), model).action, 'block');
});

test('data-class matrix, tool-arguments column', () => {
  assert.equal(toolArgDecision('secrets', act([]), pol()).exfiltration, true);
  assert.equal(toolArgDecision('payment_card', act(['payment_card']), pol()).action, 'allow');
  assert.equal(toolArgDecision('payment_card', act([]), pol()).exfiltration, true);
  assert.equal(toolArgDecision('personal', act(['personal']), pol()).action, 'allow');
  assert.equal(toolArgDecision('personal', act([]), pol()).action, 'block');
  assert.equal(toolArgDecision('legal_privileged', act([]), pol()).action, 'require_approval');
});

test('prompt inspection tokenises personal data and flags card exfiltration', () => {
  let n = 0;
  const tok = () => `<tok:x:${String(++n).padStart(12, '0')}>`;
  const ok = inspectPrompt([{ role: 'user', content: 'mail maria.lopez@mail.example' }], pol(), model, tok);
  assert.equal(ok.tokenised, 1);
  assert.equal(ok.blocked, null);
  assert.match(String(ok.messages[0]!.content), /<tok:x:/);
  const bad = inspectPrompt([{ role: 'user', content: 'card 4111 1111 1111 1111' }], pol([], ['payment_card']), model, tok);
  assert.equal(bad.exfiltration?.rule, 'RB-KILL-02');
  const tool = inspectPrompt([{ role: 'assistant', content: '', tool_calls: [{ function: { arguments: '{"key":"AKIAABCDEFGHIJKLMNOP"}' } }] }], pol(), model, tok);
  assert.equal(tool.exfiltration?.tag, 'secrets');
});

test('tool argument inspection walks nested JSON', () => {
  const r = inspectArgs({ customer: { email: 'a.b@mail.example', notes: ['key AKIAABCDEFGHIJKLMNOP'] } }, act(['personal']), pol());
  assert.equal(r.exfiltration?.tag, 'secrets');
  assert.equal(r.events.length, 2);
});

test('response cleaning redacts secrets and masks cards after restoring tokens', () => {
  const events: never[] = [];
  const out = cleanResponseText('key AKIAABCDEFGHIJKLMNOP and card 4111 1111 1111 1111 for <t>', (s) => s.replace('<t>', 'maria'), events);
  assert.equal(out, 'key [REDACTED:secret] and card **** **** **** 1111 for maria');
});
