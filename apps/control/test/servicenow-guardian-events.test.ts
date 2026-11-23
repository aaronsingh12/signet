import { strict as assert } from 'node:assert';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

process.env.MONGODB_DATABASE = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
after(dropTestDatabase);

test('observed native Guardian evidence distinguishes policy blocks, monitor-only verdicts and transformer failures', async () => {
  const { nativeGuardianCategories } = await import('../src/servicenow-guardian-events');
  const error = 'Error 300000: Check guardrail response for flagged moderation checks.';
  const metrics = [
    { name: 'Prompt Injection Setting', value: 'BLOCK' },
    { name: 'Prompt Injection', value: 'true' },
    { name: 'Raw Response', value: JSON.stringify({ security: { flagged: true, categories: ['credential_disclosure_request'] }, safety: { flagged: false, categories: [] } }) },
  ];
  assert.deepEqual(nativeGuardianCategories('300000', error, metrics), ['credential_disclosure_request']);
  assert.equal(nativeGuardianCategories('300000', error, metrics.map(metric => metric.name === 'Prompt Injection Setting' ? { ...metric, value: 'MONITOR' } : metric)), null);
  assert.equal(nativeGuardianCategories('300000', 'Response transformer failed', metrics), null);
  assert.equal(nativeGuardianCategories('500000', error, metrics), null);
  assert.equal(nativeGuardianCategories('300000', error, metrics.filter(metric => metric.name !== 'Raw Response')), null);
  assert.throws(() => nativeGuardianCategories('300000', error, [...metrics, metrics[0]!]), /ambiguous/);
});

test('a ServiceNow block links to the Signet review whose verdict it carried out', async () => {
  const { nativeGuardianCategories, signetReference } = await import('../src/servicenow-guardian-events');
  const error = 'Error 300000: Check guardrail response for flagged moderation checks.';
  const ref = 'req_01M7S5KTZAEZV9KDWFVQ20BB0S';
  const message = 'This request is blocked by Signet. Reason: prompt injection detected';
  const metrics = [
    { name: 'Prompt Injection Setting', value: 'BLOCK' },
    { name: 'Prompt Injection', value: 'true' },
    { name: 'Raw Response', value: JSON.stringify({ security: { flagged: true, categories: ['prompt_injection', message, `signet_ref:${ref}`] }, safety: { flagged: false, categories: [] } }) },
  ];
  const categories = nativeGuardianCategories('300000', error, metrics)!;
  assert.deepEqual(signetReference(categories), { categories: ['prompt_injection'], signet_request_id: ref });
  // Verdicts ServiceNow stored before the wording changed still have the message removed.
  assert.deepEqual(signetReference(['prompt_injection', 'This request was blocked by Signet: prompt injection detected', `signet_ref:${ref}`]), { categories: ['prompt_injection'], signet_request_id: ref });
  // Signet flags both fields; with Prompt Injection and Offensiveness both set to BLOCK it is still one Signet review.
  const both = [
    { name: 'Prompt Injection Setting', value: 'BLOCK' }, { name: 'Prompt Injection', value: 'true' },
    { name: 'Offensiveness Setting', value: 'BLOCK' }, { name: 'Offensiveness', value: 'true' },
    { name: 'Raw Response', value: JSON.stringify({ security: { flagged: true, categories: ['secret_disclosure', message, `signet_ref:${ref}`] }, safety: { flagged: true, categories: ['secret_disclosure', message, `signet_ref:${ref}`] } }) },
  ];
  assert.deepEqual(signetReference(nativeGuardianCategories('300000', error, both)!), { categories: ['secret_disclosure'], signet_request_id: ref });
  // A block on a verdict without a Signet reference was ServiceNow's own decision.
  assert.deepEqual(signetReference(['offensive']), { categories: ['offensive'], signet_request_id: null });
  assert.throws(() => signetReference(['signet_ref:not-a-request-id']), /malformed/);
  assert.throws(() => signetReference([`signet_ref:${ref}`, 'signet_ref:req_01M7S5KTZAEZV9KDWFVQ20BB0T']), /more than one/);
});
