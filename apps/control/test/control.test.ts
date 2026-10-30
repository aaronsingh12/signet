import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import type { CertificateBody } from '@signet/core';
import { compilePolicy, policyHash } from '../src/compile';
import { DEFAULT_GROUP_ROLES, permissionsFor, rolesFor } from '../src/rbac';

const seal = {
  cert_id: 'crt_1', agent_id: 'agt_1', version: 'v1.0', tenant: 't', owner: 'o', approvers: [], tier: 'T2', autonomy_level: 'L2',
  models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }],
  tools: [{ server: 'mcp://orders', data_scopes: ['personal'], actions: [{ name: 'issue_refund', impact: 'privileged', value_threshold_usd: 100, value_arg: 'amount', constraints: { amount: { max: 5000 } } }] }],
  data_classes: { prompt: ['personal'], forbidden: ['payment_card'] },
  hitl: [{ action: 'mcp://orders.issue_refund', arg: 'amount', gt: 2000, approver_group: 'ops-supervisors' }],
  limits: { rpm: 60, tokens_per_day: 1000, usd_per_day: 10 }, environments: ['dev'], tags: [], ai_disclosure: true,
  valid_from: '', valid_to: '', issued_at: '',
} as unknown as Omit<CertificateBody, 'policy_sha256'>;

test('policy compiler flattens tools, attaches HITL rules and is deterministic', () => {
  const p = compilePolicy(seal, { max_input_tokens: 32000, max_cost_per_request_usd: 5 });
  const a = p.actions['mcp://orders.issue_refund']!;
  assert.equal(a.impact, 'privileged');
  assert.deepEqual(a.hitl, [{ arg: 'amount', gt: 2000, approver_group: 'ops-supervisors' }]);
  assert.deepEqual(a.data_scopes, ['personal']);
  assert.equal(policyHash(p), policyHash(compilePolicy(structuredClone(seal), { max_input_tokens: 32000, max_cost_per_request_usd: 5 })));
});

test('IdP groups map to roles and roles to permissions (BP 14.2)', () => {
  const roles = rolesFor(['/signet-security-officers', 'unrelated-group'], DEFAULT_GROUP_ROLES);
  assert.deepEqual(roles, ['security_officer']);
  const perms = permissionsFor(roles);
  assert.ok(perms.includes('ladder.kill'));
  assert.ok(!perms.includes('secrets.manage'));
  assert.ok(!permissionsFor(['auditor']).some((p) => p.startsWith('ladder.')));
  assert.ok(!permissionsFor(['tenant_admin']).includes('certificates.approve')); // tenant admins cannot approve agents
});
