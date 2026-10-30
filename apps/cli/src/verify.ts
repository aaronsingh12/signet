import { createHash } from 'node:crypto';
import { createReadStream, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { createGunzip } from 'node:zlib';
import {
  REPO_ROOT, automationToken, env, fromJwk, merkleRoot, sha256, verifyChain, verifyJws,
  type LedgerRecord, type PublicJwk,
} from '@signet/core';

// signet-verify (BP 1B.2, E31): checks an Evidence Package entirely offline, without trusting the
// server that produced it. Usage:
//   npm run verify                         export a package from the control plane, then verify it
//   npm run verify -- <file.sep>           verify a package
//   npm run verify -- <file.sep> --key k.jwk   also pin the ledger key you obtained independently

interface RootPayload { day: string; first_seq: number; last_seq: number; count: number; merkle_root: string; chain_head: string }

async function exportPackage(): Promise<string> {
  const r = await fetch(`${env('SIGNET_CONTROL_URL', 'http://localhost:4100')}/api/v1/ledger/export`, { headers: { authorization: `Bearer ${await automationToken()}` } });
  if (!r.ok) throw new Error(`export failed: ${r.status} ${await r.text()}`);
  const dir = join(REPO_ROOT, 'exports');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `signet-${new Date().toISOString().replace(/[:.]/g, '-')}.sep`);
  writeFileSync(file, Buffer.from(await r.arrayBuffer()));
  return file;
}

const ok = (s: string) => console.log(`  \x1b[32m✓\x1b[0m ${s}`);
const bad = (s: string) => console.log(`  \x1b[31m✗\x1b[0m ${s}`);

async function main() {
  const args = process.argv.slice(2);
  const keyArg = args.indexOf('--key');
  const pinned = keyArg >= 0 ? (JSON.parse(readFileSync(resolve(process.cwd(), args[keyArg + 1]!), 'utf8')) as PublicJwk) : null;
  const fileArg = args.find((a, i) => !a.startsWith('--') && (keyArg < 0 || i !== keyArg + 1));
  const file = fileArg ? resolve(process.cwd(), fileArg) : await exportPackage();
  const t0 = performance.now();
  console.log(`signet-verify ${file}`);

  const hash = createHash('sha256');
  type Manifest = { format: string; record_count: number; start_prev_hash: string | null; keys: { ledger: PublicJwk }; tenant_name: string };
  let manifest = null as Manifest | null;
  const roots: { day: string; jws: string }[] = [];
  const records: LedgerRecord[] = [];
  let end: { sha256: string; signature: string } | null = null;
  const rl = createInterface({ input: createReadStream(file).pipe(createGunzip()), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line) continue;
    const obj = JSON.parse(line) as { type: string } & Record<string, unknown>;
    if (obj.type === 'end') {
      end = obj as never;
      continue;
    }
    hash.update(`${line}\n`);
    if (obj.type === 'manifest') manifest = obj as unknown as Manifest;
    else if (obj.type === 'root') roots.push(obj as never);
    else if (obj.type === 'record') records.push(obj.record as LedgerRecord);
  }
  let failed = false;
  if (!manifest || manifest.format !== 'signet-evidence-package/1') {
    bad('not a signet-evidence-package/1 file');
    process.exit(2);
  }
  const ledgerKey = manifest.keys.ledger;
  const fingerprint = sha256(String(ledgerKey.x)).slice(0, 16);
  if (pinned && pinned.x !== ledgerKey.x) {
    bad(`ledger key ${ledgerKey.kid} does not match the pinned key`);
    failed = true;
  } else ok(`ledger key ${ledgerKey.kid} · fingerprint ${fingerprint}${pinned ? ' · matches pinned key' : ' (compare with the key the tenant publishes)'}`);
  const keys = new Map([[ledgerKey.kid, fromJwk(ledgerKey)]]);

  const digest = hash.digest('hex');
  try {
    const sig = verifyJws<{ sha256: string }>(end!.signature, keys, 'signet-sep').payload;
    if (sig.sha256 !== digest || end!.sha256 !== digest) throw new Error('digest mismatch');
    ok('package signature valid; contents match the signed digest');
  } catch (e) {
    bad(`package signature or digest invalid (${(e as Error).message}): the file was altered after export`);
    failed = true;
  }

  if (records.length !== manifest.record_count) {
    bad(`manifest says ${manifest.record_count} records, package holds ${records.length}`);
    failed = true;
  }
  const chain = verifyChain(records, manifest.start_prev_hash ?? undefined);
  if (chain.ok) ok(`${chain.count.toLocaleString()} records · hash chain intact`);
  else {
    bad(`hash chain broken at seq ${chain.error!.seq} (${chain.error!.record_id}): ${chain.error!.reason}`);
    failed = true;
  }

  const bySeq = new Map(records.map((r) => [r.seq, r]));
  let rootsOk = 0;
  for (const r of roots) {
    try {
      const p = verifyJws<RootPayload>(r.jws, keys, 'signet-root').payload;
      const dayRecs: LedgerRecord[] = [];
      for (let s = p.first_seq; s <= p.last_seq; s++) {
        const rec = bySeq.get(s);
        if (rec && rec.ts.slice(0, 10) === p.day) dayRecs.push(rec);
      }
      if (dayRecs.length !== p.count) throw new Error(`root covers ${p.count} records, package has ${dayRecs.length}`);
      if (merkleRoot(dayRecs.map((x) => x.record_hash)) !== p.merkle_root) throw new Error('Merkle root does not match the records');
      if (bySeq.get(p.last_seq)?.record_hash !== p.chain_head) throw new Error('root is not tied to the chain head');
      rootsOk++;
    } catch (e) {
      bad(`daily root ${r.day}: ${(e as Error).message}`);
      failed = true;
    }
  }
  if (roots.length) {
    if (rootsOk === roots.length) ok(`${roots.length} daily Merkle roots · signatures valid · recomputed from the records`);
  } else console.log('  · no finished days in this package yet (roots are signed after 00:00 UTC)');
  console.log(`${failed ? '\x1b[31mFAILED\x1b[0m' : '\x1b[32mVERIFIED\x1b[0m'} offline in ${((performance.now() - t0) / 1000).toFixed(2)} s · ${manifest.tenant_name}`);
  process.exit(failed ? 2 : 0);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
