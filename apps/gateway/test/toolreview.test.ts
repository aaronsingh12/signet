import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import type { CertificateBody, CompiledAction, CompiledPolicy } from '@signet/core';
import { Halt, newCtx } from '../src/ctx';
import type { ChatResponse } from '../src/provider';
import { actionKeysFor, blockedAnswer, proposedCalls, reviewProposedCalls } from '../src/toolreview';

const action = (key: string, over: Partial<CompiledAction> = {}): CompiledAction => ({ key, impact: 'read', value_threshold_usd: null, value_arg: null, constraints: {}, data_scopes: [], hitl: [], ...over });
const KEY = 'http://agent-tools.lookup_order';
const REFUND = 'http://agent-tools.create_refund';
const policy = { cert_id: 'c', agent_id: 'a', version: '1', tier: 'T3', autonomy_level: 'L3', models: ['beam:cloud'], prompt_tags: [], forbidden_tags: [], max_input_tokens: 1000, max_cost_per_request_usd: 1,
  actions: { [KEY]: action(KEY), [REFUND]: action(REFUND, { impact: 'write', constraints: { amount: { max: 100 } } }) } } as unknown as CompiledPolicy;
const answer = (name: string, args: string): ChatResponse => ({ choices: [{ index: 0, message: { role: 'assistant', content: '', tool_calls: [{ id: 'c1', type: 'function', function: { name, arguments: args } }] } }] });

function ctxOf(shadow = false) {
  const ctx = newCtx('llm_call', 'beam:cloud', {});
  ctx.cert = { tier: 'T3', limits: {} } as unknown as CertificateBody;
  ctx.claims = { agent_id: 'a' } as typeof ctx.claims;
  ctx.sessionId = `s-${Math.random()}`;
  ctx.shadow = shadow;
  return ctx;
}
const review = (ctx: ReturnType<typeof ctxOf>, r: ChatResponse) => reviewProposedCalls(ctx, {}, r, policy, false, (s) => s);
const refused = (code: string) => (e: unknown) => e instanceof Halt && e.code === code;

test('finds the proposed calls and the seal actions they name', () => {
  assert.deepEqual(proposedCalls(answer('lookup_order', '{}')), [{ name: 'lookup_order', args: '{}' }]);
  assert.deepEqual(proposedCalls({ choices: [{ index: 0, message: { role: 'assistant', content: 'hi' } }] }), []);
  assert.deepEqual(actionKeysFor(policy, 'lookup_order'), [KEY]);
  assert.deepEqual(actionKeysFor(policy, 'order'), []);
});

test('a blocked answer gives the reason and leaves no tool to run', () => {
  const r = answer('delete_everything', '{}');
  blockedAnswer(r, 'not in the seal');
  assert.deepEqual(proposedCalls(r), []);
  assert.equal(r.choices![0]!.message.content, 'Chat blocked by Signet. This action was blocked by company policy. Reason: not in the seal.');
  assert.equal(r.choices![0]!.finish_reason, 'stop');
});

test('a call the seal allows passes', async () => {
  await review(ctxOf(), answer('lookup_order', '{"id":"1"}'));
  await review(ctxOf(), answer('create_refund', '{"amount":50}'));
});

test('a tool outside the seal never reaches the agent', async () => {
  await assert.rejects(review(ctxOf(), answer('delete_everything', '{}')), refused('tool_call_blocked'));
});

test('arguments over a seal limit are refused', async () => {
  await assert.rejects(review(ctxOf(), answer('create_refund', '{"amount":5000}')), refused('policy_denied'));
});

test('unreadable arguments are refused, not waved through', async () => {
  await assert.rejects(review(ctxOf(), answer('create_refund', '{"amount":')), refused('tool_call_blocked'));
});

test('shadow records what it would block and lets the answer through', async () => {
  const ctx = ctxOf(true);
  await review(ctx, answer('delete_everything', '{}'));
  await review(ctx, answer('create_refund', '{"amount":5000}'));
  assert.equal(ctx.wouldBlock.length, 2);
});

test('a secret in the arguments is stopped even in shadow', async () => {
  await assert.rejects(review(ctxOf(true), answer('lookup_order', '{"note":"key AKIAIOSFODNN7EXAMPLE"}')), refused('data_exfiltration'));
});
