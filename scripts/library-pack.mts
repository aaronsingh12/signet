// Library packs (BP 9.4 "signed .ppack bundles from TechSnitch"). Run by TechSnitch's release process,
// never on a customer's Signet server.
//
//   npx tsx scripts/library-pack.mts keygen <dir>
//       Creates an Ed25519 pack-signing key: <dir>/pack-signing-key.json (PRIVATE: keep it offline or in
//       a vault) and <dir>/pack-signing-key.public.json (give its JSON to customers as
//       SIGNET_LIBRARY_TRUSTED_KEYS).
//   npx tsx scripts/library-pack.mts build <private key file> [out file] --db <postgres url>
//       Builds the library pack of this release (version from LIBRARY_VERSION) and signs it. The control
//       definitions load with the control-plane modules, which need a database: give a scratch one with
//       --db (any DATABASE_URL in the shell is ignored). A throwaway schema is used and dropped.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateSigningKey, loadSigningKey, toJwk, ulid, type StoredKey } from '@signet/core';

const argv = process.argv.slice(2);
const dbAt = argv.indexOf('--db');
const dbUrl = dbAt >= 0 ? argv[dbAt + 1] : undefined;
if (dbAt >= 0) argv.splice(dbAt, 2);
const [cmd, a, b] = argv;
if (cmd === 'keygen') {
  if (!a) throw new Error('usage: keygen <dir>');
  mkdirSync(a, { recursive: true });
  const priv = join(a, 'pack-signing-key.json');
  if (existsSync(priv)) throw new Error(`${priv} already exists; not overwriting a signing key`);
  const stored = generateSigningKey(`pack-${ulid()}`);
  writeFileSync(priv, JSON.stringify(stored, null, 2), { mode: 0o600 });
  writeFileSync(join(a, 'pack-signing-key.public.json'), JSON.stringify({ keys: [toJwk(loadSigningKey(stored))] }, null, 2));
  console.log(`private key: ${priv} (keep it secret)\npublic key:  ${join(a, 'pack-signing-key.public.json')} (SIGNET_LIBRARY_TRUSTED_KEYS)`);
} else if (cmd === 'build') {
  if (!a || !dbUrl) throw new Error('usage: build <private key file> [out file] --db <scratch postgres url>');
  process.env.DATABASE_URL = dbUrl; // never a DATABASE_URL from the shell or .env
  process.env.SIGNET_DB_SCHEMA = `pack_build_${Date.now()}`;
  const { builtInPack, signPack } = await import('../apps/control/src/library');
  const { db } = await import('../apps/control/src/db');
  const key = loadSigningKey(JSON.parse(readFileSync(a, 'utf8')) as StoredKey);
  const pack = builtInPack();
  const out = b ?? `signet-library-${pack.version}.ppack`;
  writeFileSync(out, JSON.stringify(signPack(pack, key)));
  await db.exec(`DROP SCHEMA "${process.env.SIGNET_DB_SCHEMA}" CASCADE`);
  console.log(`${out}: version ${pack.version}, ${pack.content.frameworks.length} frameworks, ${pack.content.requirements.length} requirements, sha256 ${pack.sha256.slice(0, 16)}…, signed by ${key.kid}`);
  process.exit(0);
} else {
  console.log('usage: library-pack.mts keygen <dir> | build <private key file> [out file]');
}
