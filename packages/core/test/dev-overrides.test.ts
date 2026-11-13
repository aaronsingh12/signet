import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { devOverridesAllowed } from '../src/env';

// Dev shortcuts (skip a shadow period or a detector trial) work on a laptop only, never on hosted Signet.
test('dev shortcuts: laptop yes; Vercel, production builds or non-dev environments no', () => {
  const saved = { env: process.env.SIGNET_ENV, vercel: process.env.VERCEL, node: process.env.NODE_ENV };
  const set = (env?: string, vercel?: string, node?: string) => {
    for (const [k, v] of [['SIGNET_ENV', env], ['VERCEL', vercel], ['NODE_ENV', node]] as const) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  };
  try {
    set(undefined, undefined, undefined); assert.equal(devOverridesAllowed(), true);
    set('dev', '1', undefined); assert.equal(devOverridesAllowed(), false);
    set('dev', undefined, 'production'); assert.equal(devOverridesAllowed(), false);
    set('prod', undefined, undefined); assert.equal(devOverridesAllowed(), false);
  } finally {
    set(saved.env, saved.vercel, saved.node);
  }
});
