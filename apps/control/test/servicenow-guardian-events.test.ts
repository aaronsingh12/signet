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
