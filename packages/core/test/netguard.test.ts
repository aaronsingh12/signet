import { strict as assert } from 'node:assert';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { DestinationBlocked, addressAllowed, checkDestination, classifyAddress, guardedLookup, request } from '../src/index';

test('address classes: metadata and link-local are never reachable; private only when allowed', () => {
  assert.equal(classifyAddress('169.254.169.254'), 'link_local');
  assert.equal(classifyAddress('::ffff:169.254.169.254'), 'link_local');
  assert.equal(classifyAddress('::ffff:a9fe:a9fe'), 'link_local');
  assert.equal(classifyAddress('0:0:0:0:0:ffff:7f00:1'), 'loopback');
  assert.equal(classifyAddress('10.1.2.3'), 'private');
  assert.equal(classifyAddress('172.31.0.1'), 'private');
  assert.equal(classifyAddress('172.32.0.1'), 'public');
  assert.equal(classifyAddress('127.0.0.1'), 'loopback');
  assert.equal(classifyAddress('fd00::1'), 'private');
  assert.equal(classifyAddress('8.8.8.8'), 'public');
  assert.equal(addressAllowed('169.254.169.254', { allowPrivate: true }).ok, false);
  assert.equal(addressAllowed('10.0.0.5', { allowPrivate: false }).ok, false);
  assert.equal(addressAllowed('10.0.0.5', { allowPrivate: true }).ok, true);
});

test('registration check refuses metadata, private (unless allowed) and credentials in URLs', async () => {
  await assert.rejects(checkDestination('http://169.254.169.254/latest/meta-data', { allowPrivate: true }), DestinationBlocked);
  await assert.rejects(checkDestination('http://127.0.0.1:9/', { allowPrivate: false }), DestinationBlocked);
  await assert.rejects(checkDestination('http://localhost:9/', { allowPrivate: false }), DestinationBlocked); // resolves to loopback
  await assert.rejects(checkDestination('http://user:pw@example.com/', { allowPrivate: true }), DestinationBlocked);
  await assert.rejects(checkDestination('file:///etc/passwd', { allowPrivate: true }), DestinationBlocked);
  assert.deepEqual((await checkDestination('http://127.0.0.1:9/', { allowPrivate: true })).addresses, ['127.0.0.1']);
});

test('guarded requests check the address actually dialled', async () => {
  const srv = createServer((_q, r) => r.end('{"ok":true}')).listen(0);
  const port = (srv.address() as { port: number }).port;
  try {
    await assert.rejects(request(`http://localhost:${port}/`, { destination: { allowPrivate: false } }), /may not reach|not a reachable/);
    await assert.rejects(request(`http://127.0.0.1:${port}/`, { destination: { allowPrivate: false } }), DestinationBlocked);
    const ok = await request(`http://localhost:${port}/`, { destination: { allowPrivate: true } });
    assert.equal(ok.status, 200);
    await assert.rejects(request(`http://localhost:${port}/`, { destination: { allowPrivate: true }, maxBytes: 3 }), /larger than 3 bytes/);
  } finally {
    srv.close();
  }
});


test('DNS rebinding is checked at socket lookup even after a public registration lookup', async (context) => {
  let lookups = 0;
  context.mock.method(dns, 'lookup', ((_host: string, _options: object, callback: (error: Error | null, addresses: { address: string; family: number }[]) => void) => callback(null, [{ address: ++lookups === 1 ? '93.184.216.34' : '127.0.0.1', family: 4 }])) as typeof dns.lookup);
  syncBuiltinESMExports();
  context.after(() => { context.mock.restoreAll(); syncBuiltinESMExports(); });
  await checkDestination('https://rebind.example/', { allowPrivate: false });
  await assert.rejects(new Promise<void>((resolve, reject) => guardedLookup({ allowPrivate: false })('rebind.example', {}, (error) => error ? reject(error) : resolve())), DestinationBlocked);
  assert.equal(lookups, 2);
  assert.equal(classifyAddress('198.18.0.1'), 'reserved');
  assert.equal(classifyAddress('2001:db8::1'), 'reserved');
});
