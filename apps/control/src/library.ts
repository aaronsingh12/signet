import { canonicalize, fromJwk, sha256, signJws, verifyJws, type PublicJwk, type SigningKey } from '@signet/core';
import type { KeyObject } from 'node:crypto';
import { appliedSha, applyContent, builtInContent, type LibraryContent } from './controls';
import { db, nowIso } from './db';
import { forbidden, invalid, notFound } from './errors';
import { LIBRARY_RELEASED, LIBRARY_VERSION } from './frameworks';
import * as ledger from './ledger';
import { notifyRoles } from './notify';
import type { Principal } from './rbac';

// Library packs (BP 9.1 "the library is released as signed packs (semantic versioning). Tenants choose
// when to adopt a new pack; the diff is shown before adoption", 9.4 "signed .ppack bundles from
// TechSnitch, online update or offline import").
//
// The library built into this release is a pack. In 'auto' mode (the default) it is adopted as soon as
// it is deployed, as before; in 'review' mode it waits as "available" with its diff until a person
// adopts it. A pack file (.ppack) can also be imported offline: it is accepted only if its signature is
// valid for a key in SIGNET_LIBRARY_TRUSTED_KEYS (TechSnitch's public pack-signing keys). Every import
// and adoption is written to the ledger.

export const FORMAT = 'signet-library-pack/1';
export interface Pack { format: string; version: string; released: string; sha256: string; content: LibraryContent }
export interface PackFile { pack: Pack; signature: string }

const SYSTEM = 'system';

export function builtInPack(): Pack {
  const content = builtInContent();
  return { format: FORMAT, version: LIBRARY_VERSION, released: LIBRARY_RELEASED, sha256: sha256(canonicalize(content)), content };
}

/** Sign a pack (scripts/library-pack.mts). The private key never comes near a Signet server. */
export const signPack = (pack: Pack, key: SigningKey): PackFile => ({ pack, signature: signJws({ format: FORMAT, version: pack.version, sha256: pack.sha256 }, key, 'signet-library-pack') });

export async function mode(): Promise<'auto' | 'review'> {
  const v = ((await db.prepare("SELECT value FROM library_state WHERE key = 'adoption_mode'").get()) as { value: string } | undefined)?.value;
  return v === 'review' ? 'review' : 'auto';
}

export async function setMode(m: string, p: Principal) {
  if (m !== 'auto' && m !== 'review') throw invalid("mode must be 'auto' or 'review'");
  if (p.kind !== 'human') throw forbidden('RBAC', 'library adoption settings are changed by people');
  await db.prepare("INSERT INTO library_state (key, value, updated_at) VALUES ('adoption_mode', ?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at").run(m, nowIso());
  await ledger.append({ kind: 'admin', data: { event: 'library.adoption_mode', mode: m, actor: p.id } });
  return { mode: m };
}

async function store(pack: Pack, source: 'built_in' | 'import', signer: string | null): Promise<string> {
  const id = `${source === 'built_in' ? 'builtin' : 'import'}-${pack.version}-${pack.sha256.slice(0, 12)}`;
  await db.prepare("INSERT INTO library_pack (id, version, released, sha256, source, signer, content, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'available', ?) ON CONFLICT (id) DO NOTHING")
    .run(id, pack.version, pack.released, pack.sha256, source, signer, JSON.stringify(pack.content), nowIso());
  return id;
}

/** On start-up: record the built-in pack; adopt it now in auto mode (or on a fresh database), else wait for review. */
export async function syncBuiltIn() {
  const pack = builtInPack();
  const applied = await appliedSha();
  if (applied === pack.sha256) return;
  const id = await store(pack, 'built_in', null);
  if (!applied || (await mode()) === 'auto') {
    await adopt(id, null);
    return;
  }
  const row = (await db.prepare('SELECT notified_at FROM library_pack WHERE id = ?').get(id)) as { notified_at: string | null };
  if (!row.notified_at) {
    await notifyRoles(['tenant_admin'], 'library', `Signet library ${pack.version} is ready to review and adopt`, '/controls');
    await db.prepare('UPDATE library_pack SET notified_at = ? WHERE id = ?').run(nowIso(), id);
  }
}

// --- diff -----------------------------------------------------------------------------------------------
export interface PackDiff {
  frameworks: { added: string[]; removed: string[]; changed: string[] };
  requirements: { added: number; removed: number; changed: number; by_framework: Record<string, { added: number; removed: number; changed: number }> };
  mappings: { added: number; removed: number };
  controls: { added: string[]; removed: string[]; changed: string[] };
  previous: string | null;
}

export function diff(from: LibraryContent | null, to: LibraryContent): PackDiff {
  const a = from ?? { controls: [], frameworks: [], placeholders: [], requirements: [] };
  const byId = <T extends { id: string }>(xs: T[]) => new Map(xs.map((x) => [x.id, canonicalize(x)]));
  const cmp = <T extends { id: string }>(x: T[], y: T[]) => {
    const A = byId(x); const B = byId(y);
    return { added: [...B.keys()].filter((k) => !A.has(k)), removed: [...A.keys()].filter((k) => !B.has(k)), changed: [...B.keys()].filter((k) => A.has(k) && A.get(k) !== B.get(k)) };
  };
  const reqKey = (r: { framework_id: string; external_id: string }) => `${r.framework_id}|${r.external_id}`;
  const RA = new Map(a.requirements.map((r) => [reqKey(r), r]));
  const RB = new Map(to.requirements.map((r) => [reqKey(r), r]));
  const by: PackDiff['requirements']['by_framework'] = {};
  const bump = (fw: string, k: 'added' | 'removed' | 'changed') => { (by[fw] ??= { added: 0, removed: 0, changed: 0 })[k]++; };
  let added = 0; let removed = 0; let changed = 0;
  for (const [k, r] of RB) { const o = RA.get(k); if (!o) { added++; bump(r.framework_id, 'added'); } else if (o.summary !== r.summary) { changed++; bump(r.framework_id, 'changed'); } }
  for (const [k, r] of RA) if (!RB.has(k)) { removed++; bump(r.framework_id, 'removed'); }
  const maps = (c: LibraryContent) => new Set(c.requirements.flatMap((r) => r.maps.map((m) => `${reqKey(r)}>${m.control}:${m.rel}`)));
  const MA = maps(a); const MB = maps(to);
  return {
    frameworks: cmp([...a.frameworks, ...a.placeholders], [...to.frameworks, ...to.placeholders]),
    requirements: { added, removed, changed, by_framework: by },
    mappings: { added: [...MB].filter((x) => !MA.has(x)).length, removed: [...MA].filter((x) => !MB.has(x)).length },
    controls: cmp(a.controls, to.controls),
    previous: null,
  };
}

async function adoptedRow() {
  return (await db.prepare("SELECT id, version, content FROM library_pack WHERE status = 'adopted' ORDER BY adopted_at DESC LIMIT 1").get()) as { id: string; version: string; content: string } | undefined;
}

export async function diffOf(id: string): Promise<PackDiff> {
  const row = (await db.prepare('SELECT content FROM library_pack WHERE id = ?').get(id)) as { content: string } | undefined;
  if (!row) throw notFound(`library pack ${id}`);
  const cur = await adoptedRow();
  return { ...diff(cur ? JSON.parse(cur.content) : null, JSON.parse(row.content)), previous: cur?.version ?? null };
}

/** Apply a stored pack to this tenant's library. p = null: adopted automatically (auto mode or first start). */
export async function adopt(id: string, p: Principal | null) {
  if (p && p.kind !== 'human') throw forbidden('RBAC', 'library packs are adopted by people');
  const row = (await db.prepare('SELECT * FROM library_pack WHERE id = ?').get(id)) as { id: string; version: string; sha256: string; source: string; signer: string | null; content: string; status: string } | undefined;
  if (!row) throw notFound(`library pack ${id}`);
  const d = await diffOf(id);
  const content = JSON.parse(row.content) as LibraryContent;
  await applyContent(content, row.sha256);
  await db.prepare("UPDATE library_pack SET status = 'superseded' WHERE status = 'adopted' AND id <> ?").run(id);
  await db.prepare("UPDATE library_pack SET status = 'adopted', adopted_at = ?, adopted_by = ? WHERE id = ?").run(nowIso(), p?.id ?? SYSTEM, id);
  await ledger.append({ kind: 'admin', data: {
    event: 'library.pack_adopted', pack_id: id, version: row.version, sha256: row.sha256, source: row.source, signer: row.signer, previous: d.previous,
    changes: { frameworks: d.frameworks, requirements: { added: d.requirements.added, removed: d.requirements.removed, changed: d.requirements.changed }, mappings: d.mappings, controls: d.controls },
    automatic: !p, actor: p?.id ?? SYSTEM,
  } });
  return { id, version: row.version, diff: d };
}

// --- offline import -----------------------------------------------------------------------------------
/** TechSnitch's public pack-signing keys: SIGNET_LIBRARY_TRUSTED_KEYS is a JWKS ({"keys": [...]}) or a list of JWKs. */
export function trustedKeys(env = process.env): Map<string, KeyObject> {
  const raw = env.SIGNET_LIBRARY_TRUSTED_KEYS?.trim();
  if (!raw) return new Map();
  const parsed = JSON.parse(raw) as { keys?: PublicJwk[] } | PublicJwk[];
  const list = Array.isArray(parsed) ? parsed : parsed.keys ?? [];
  return new Map(list.map((k) => [k.kid, fromJwk(k)]));
}

export async function importPack(file: PackFile, p: Principal) {
  if (p.kind !== 'human') throw forbidden('RBAC', 'library packs are imported by people');
  const keys = trustedKeys();
  if (!keys.size) throw invalid('no trusted pack-signing keys are configured (SIGNET_LIBRARY_TRUSTED_KEYS)');
  if (!file?.pack || typeof file.signature !== 'string') throw invalid('a .ppack file has "pack" and "signature"');
  let payload: { format: string; version: string; sha256: string };
  let kid: string;
  try {
    const v = verifyJws<{ format: string; version: string; sha256: string }>(file.signature, keys, 'signet-library-pack');
    payload = v.payload; kid = v.header.kid;
  } catch (e) {
    throw invalid(`the pack signature is not valid for a trusted key: ${(e as Error).message}`);
  }
  const content = file.pack.content;
  if (!content || !Array.isArray(content.frameworks) || !Array.isArray(content.requirements) || !Array.isArray(content.controls) || !Array.isArray(content.placeholders)) throw invalid('the pack has no library content');
  const digest = sha256(canonicalize(content));
  if (payload.format !== FORMAT || file.pack.format !== FORMAT) throw invalid(`unsupported pack format (expected ${FORMAT})`);
  if (digest !== payload.sha256 || digest !== file.pack.sha256 || payload.version !== file.pack.version) throw invalid('the pack content does not match its signature');
  const id = await store({ ...file.pack, sha256: digest }, 'import', kid);
  await ledger.append({ kind: 'admin', data: { event: 'library.pack_imported', pack_id: id, version: file.pack.version, sha256: digest, signer: kid, actor: p.id } });
  return { id, version: file.pack.version, signer: kid, diff: await diffOf(id) };
}

export async function list() {
  const rows = (await db.prepare('SELECT id, version, released, sha256, source, signer, status, created_at, adopted_at, adopted_by FROM library_pack ORDER BY created_at DESC LIMIT 50').all()) as { id: string; status: string }[];
  return { mode: await mode(), built_in: { version: LIBRARY_VERSION, released: LIBRARY_RELEASED, sha256: builtInPack().sha256 }, items: rows };
}
