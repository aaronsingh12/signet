import { randomUUID } from 'node:crypto';
import { canonicalize, newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';

// AI Bill of Materials and vulnerability scanning (BP 6 Stage 3, 7; E16; control SGC-SUPPLY-001/002).
// For each agent Signet builds a CycloneDX 1.6 AIBOM from what it knows (models, tools and data scopes
// from the seal; framework, runtime, provider and vendor from the registry) and merges the agent's own
// SBOM when the owner uploads one (CycloneDX or SPDX JSON). Every package with a purl is checked against
// OSV.dev (which aggregates GitHub Security Advisories, NVD-linked CVEs and the language ecosystems);
// anything on CISA's Known Exploited Vulnerabilities list is raised to critical. Rescanned nightly.
//
//   SIGNET_OSV_URL   default https://api.osv.dev
//   SIGNET_KEV_URL   default https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

const OSV = () => (process.env.SIGNET_OSV_URL ?? 'https://api.osv.dev').replace(/\/$/, '');
const KEV = () => process.env.SIGNET_KEV_URL ?? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const MAX_COMPONENTS = 5000;
const MAX_DETAILS = 300;

interface Component { 'bom-ref': string; type: string; name: string; version?: string; purl?: string; group?: string; supplier?: { name: string }; description?: string; properties?: { name: string; value: string }[] }
interface Service { 'bom-ref': string; name: string; endpoints?: string[]; data?: { flow: string; classification: string }[]; properties?: { name: string; value: string }[] }
export interface CycloneDx { bomFormat: 'CycloneDX'; specVersion: '1.6'; serialNumber: string; version: number; metadata: Record<string, unknown>; components: Component[]; services: Service[] }

// --- Reading an uploaded SBOM ---------------------------------------------------------------------
function uploadedComponents(sbom: unknown): Component[] {
  if (!sbom || typeof sbom !== 'object') return [];
  const s = sbom as Record<string, unknown>;
  const out: Component[] = [];
  if (s.bomFormat === 'CycloneDX' && Array.isArray(s.components)) {
    const walk = (list: unknown[]) => {
      for (const c of list as Record<string, unknown>[]) {
        if (typeof c?.name === 'string') out.push({ 'bom-ref': `pkg:${out.length}`, type: String(c.type ?? 'library'), name: c.name, ...(c.version ? { version: String(c.version) } : {}), ...(typeof c.purl === 'string' ? { purl: c.purl } : {}), ...(c.group ? { group: String(c.group) } : {}) });
        if (Array.isArray(c?.components)) walk(c.components);
      }
    };
    walk(s.components);
  } else if (typeof s.spdxVersion === 'string' && Array.isArray(s.packages)) {
    for (const p of s.packages as Record<string, unknown>[]) {
      const purl = ((p.externalRefs ?? []) as { referenceType?: string; referenceLocator?: string }[]).find((r) => r.referenceType === 'purl')?.referenceLocator;
      if (typeof p.name === 'string') out.push({ 'bom-ref': `pkg:${out.length}`, type: 'library', name: p.name, ...(p.versionInfo ? { version: String(p.versionInfo) } : {}), ...(purl ? { purl } : {}) });
    }
  } else {
    throw invalid('the uploaded SBOM must be CycloneDX or SPDX JSON');
  }
  if (out.length > MAX_COMPONENTS) throw invalid(`the SBOM has ${out.length} components; the limit is ${MAX_COMPONENTS}`);
  return out;
}

// --- Building the AIBOM -----------------------------------------------------------------------------
interface AgentRow { id: string; handle: string; name: string; tier: string; framework: string | null; runtime: string | null; model_provider: string | null; vendor: string | null }
interface SealBody { version?: string; cert_id?: string; models?: { model: string; region?: string }[]; tools?: { server: string; actions?: { name: string; impact?: string }[]; data_scopes?: string[] }[] }

export function buildAibom(agent: AgentRow, seal: SealBody | null, uploaded: Component[]): CycloneDx {
  const components: Component[] = [];
  const prop = (name: string, value: string | undefined | null) => (value ? [{ name, value }] : []);
  for (const m of seal?.models ?? []) {
    components.push({ 'bom-ref': `model:${m.model}`, type: 'machine-learning-model', name: m.model, ...(agent.model_provider ? { supplier: { name: agent.model_provider } } : {}), properties: [...prop('signet:region', m.region)] });
  }
  if (agent.framework) components.push({ 'bom-ref': 'framework', type: 'framework', name: agent.framework });
  if (agent.runtime) components.push({ 'bom-ref': 'runtime', type: 'platform', name: agent.runtime });
  if (agent.vendor) components.push({ 'bom-ref': 'vendor-platform', type: 'platform', name: agent.vendor, supplier: { name: agent.vendor } });
  const seen = new Set(components.map((c) => c.purl ?? `${c.name}@${c.version ?? ''}`));
  for (const c of uploaded) {
    const key = c.purl ?? `${c.name}@${c.version ?? ''}`;
    if (!seen.has(key)) { seen.add(key); components.push(c); }
  }
  const services: Service[] = (seal?.tools ?? []).map((t) => ({
    'bom-ref': `tool:${t.server}`, name: t.server,
    data: (t.data_scopes ?? []).map((c) => ({ flow: 'outbound', classification: c })),
    properties: (t.actions ?? []).map((a) => ({ name: 'signet:action', value: `${a.name}${a.impact ? ` (${a.impact})` : ''}` })),
  }));
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: `urn:uuid:${randomUUID()}`, version: 1,
    metadata: {
      timestamp: nowIso(),
      tools: { components: [{ type: 'application', name: 'signet', group: 'techsnitch' }] },
      component: { 'bom-ref': 'agent', type: 'application', name: agent.handle, version: seal?.version ?? 'unsealed', description: agent.name, properties: [{ name: 'signet:agent_id', value: agent.id }, { name: 'signet:tier', value: agent.tier }, ...prop('signet:cert_id', seal?.cert_id)] },
    },
    components, services,
  };
}

export async function generate(agentId: string, input: { sbom?: unknown }, p: Principal) {
  const agent = (await db.prepare('SELECT id, handle, name, tier, framework, runtime, model_provider, vendor FROM agent WHERE id = ? OR handle = ?').get(agentId, agentId)) as AgentRow | undefined;
  if (!agent) throw notFound(`agent ${agentId}`);
  const cert = (await db.prepare("SELECT body FROM certificate WHERE agent_id = ? AND status = 'active' ORDER BY valid_from DESC LIMIT 1").get(agent.id)) as { body: string } | undefined;
  const draft = !cert ? ((await db.prepare("SELECT data FROM lifecycle WHERE agent_id = ? ORDER BY started_at DESC LIMIT 1").get(agent.id)) as { data: string } | undefined) : undefined;
  const seal = cert ? (JSON.parse(cert.body) as SealBody) : draft ? ((JSON.parse(draft.data).manifest ?? null) as SealBody | null) : null;
  // Keep components from the last uploaded SBOM when no new one is given.
  const previous = (await db.prepare('SELECT uploaded FROM aibom WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1').get(agent.id)) as { uploaded: string | null } | undefined;
  const uploaded = input.sbom !== undefined ? uploadedComponents(input.sbom) : previous?.uploaded ? (JSON.parse(previous.uploaded) as Component[]) : [];
  const bom = buildAibom(agent, seal, uploaded);
  const hash = sha256(canonicalize({ components: bom.components, services: bom.services, metadata: { component: bom.metadata.component } }));
  const id = newId('evt').replace('evt_', 'abm_');
  await tx(async () => {
    await db.prepare('INSERT INTO aibom (id, agent_id, bom, sha256, uploaded, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, agent.id, JSON.stringify(bom), hash, uploaded.length ? JSON.stringify(uploaded) : null, p.id, nowIso());
    await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'aibom.generated', aibom_id: id, sha256: hash, components: bom.components.length, services: bom.services.length, uploaded_components: uploaded.length, actor: p.id } });
  });
  const scan = await scanAibom(id);
  return { aibom_id: id, sha256: hash, components: bom.components.length, services: bom.services.length, ...scan };
}

// --- Vulnerability scanning -------------------------------------------------------------------------
interface OsvVuln { id: string; aliases?: string[]; summary?: string; details?: string; severity?: { type: string; score: string }[]; database_specific?: { severity?: string } }

let kevCache: { ids: Set<string>; at: number } | null = null;
export async function kevIds(): Promise<Set<string>> {
  if (kevCache && Date.now() - kevCache.at < 86_400_000) return kevCache.ids;
  try {
    const r = await fetch(KEV(), { signal: AbortSignal.timeout(20_000) });
    if (!r.ok) throw new Error(String(r.status));
    const j = (await r.json()) as { vulnerabilities?: { cveID: string }[] };
    kevCache = { ids: new Set((j.vulnerabilities ?? []).map((v) => v.cveID)), at: Date.now() };
  } catch (e) {
    console.error(`[control] CISA KEV feed unavailable: ${(e as Error).message}`);
    kevCache ??= { ids: new Set(), at: 0 };
  }
  return kevCache.ids;
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, moderate: 2, medium: 2, low: 1, unknown: 0 };
const severityOf = (v: OsvVuln): string => {
  const s = (v.database_specific?.severity ?? '').toLowerCase();
  if (s in SEVERITY_RANK) return s === 'moderate' ? 'medium' : s;
  return 'unknown';
};

export async function scanAibom(aibomId: string): Promise<{ scanned: number; findings: number; critical: number; kev: number; error?: string }> {
  const row = (await db.prepare('SELECT agent_id, bom FROM aibom WHERE id = ?').get(aibomId)) as { agent_id: string; bom: string } | undefined;
  if (!row) throw notFound(`aibom ${aibomId}`);
  const bom = JSON.parse(row.bom) as CycloneDx;
  const purls = [...new Set(bom.components.map((c) => c.purl).filter((x): x is string => !!x && /@/.test(x)))];
  if (!purls.length) return { scanned: 0, findings: 0, critical: 0, kev: 0 };
  try {
    const ids: { purl: string; id: string }[] = [];
    for (let i = 0; i < purls.length; i += 500) {
      const chunk = purls.slice(i, i + 500);
      const r = await fetch(`${OSV()}/v1/querybatch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: chunk.map((purl) => ({ package: { purl } })) }), signal: AbortSignal.timeout(30_000) });
      if (!r.ok) throw new Error(`OSV answered ${r.status}`);
      const j = (await r.json()) as { results: { vulns?: { id: string }[] }[] };
      j.results.forEach((res, k) => (res.vulns ?? []).forEach((v) => ids.push({ purl: chunk[k]!, id: v.id })));
    }
    const kev = await kevIds();
    const details = new Map<string, OsvVuln>();
    for (const id of [...new Set(ids.map((x) => x.id))].slice(0, MAX_DETAILS)) {
      const r = await fetch(`${OSV()}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(20_000) });
      if (r.ok) details.set(id, (await r.json()) as OsvVuln);
    }
    const now = nowIso();
    let critical = 0;
    let kevCount = 0;
    await tx(async () => {
      for (const { purl, id } of ids) {
        const v = details.get(id) ?? { id };
        const cves = [id, ...(v.aliases ?? [])].filter((a) => a.startsWith('CVE-'));
        const inKev = cves.some((c) => kev.has(c));
        const severity = inKev ? 'critical' : severityOf(v);
        if (severity === 'critical') critical++;
        if (inKev) kevCount++;
        await db.prepare(
          `INSERT INTO vulnerability_finding (agent_id, component, vuln_id, aliases, severity, kev, summary, cvss, status, first_seen, last_seen, aibom_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
           ON CONFLICT (agent_id, component, vuln_id) DO UPDATE SET aliases = EXCLUDED.aliases, severity = EXCLUDED.severity, kev = EXCLUDED.kev, summary = EXCLUDED.summary, cvss = EXCLUDED.cvss, last_seen = EXCLUDED.last_seen, aibom_id = EXCLUDED.aibom_id,
             status = CASE WHEN vulnerability_finding.status = 'fixed' THEN 'open' ELSE vulnerability_finding.status END`,
        ).run(row.agent_id, purl, id, JSON.stringify(v.aliases ?? []), severity, inKev ? 1 : 0, (v.summary ?? v.details ?? '').slice(0, 300), v.severity?.[0]?.score ?? null, now, now, aibomId);
      }
      // Components no longer affected: their open findings are closed as fixed.
      const current = new Set(ids.map((x) => `${x.purl} ${x.id}`));
      const open = (await db.prepare("SELECT component, vuln_id FROM vulnerability_finding WHERE agent_id = ? AND status = 'open'").all(row.agent_id)) as { component: string; vuln_id: string }[];
      for (const f of open.filter((o) => !current.has(`${o.component} ${o.vuln_id}`))) await db.prepare("UPDATE vulnerability_finding SET status = 'fixed', last_seen = ? WHERE agent_id = ? AND component = ? AND vuln_id = ?").run(now, row.agent_id, f.component, f.vuln_id);
      await db.prepare('UPDATE aibom SET scanned_at = ? WHERE id = ?').run(now, aibomId);
      await ledger.append({ kind: 'lifecycle', agent_id: row.agent_id, data: { event: 'aibom.scanned', aibom_id: aibomId, packages: purls.length, findings: ids.length, critical, kev: kevCount, source: 'osv.dev + CISA KEV' } });
    });
    return { scanned: purls.length, findings: ids.length, critical, kev: kevCount };
  } catch (e) {
    return { scanned: purls.length, findings: 0, critical: 0, kev: 0, error: `vulnerability scan failed: ${(e as Error).message}` };
  }
}

/** Latest AIBOM of an agent with its open findings, most severe first. */
export async function latest(agentId: string) {
  const a = (await db.prepare('SELECT id FROM agent WHERE id = ? OR handle = ?').get(agentId, agentId)) as { id: string } | undefined;
  if (!a) throw notFound(`agent ${agentId}`);
  const bom = (await db.prepare('SELECT id, bom, sha256, created_at, created_by, scanned_at FROM aibom WHERE agent_id = ? ORDER BY created_at DESC LIMIT 1').get(a.id)) as { id: string; bom: string; sha256: string; created_at: string; created_by: string; scanned_at: string | null } | undefined;
  const findings = ((await db.prepare("SELECT component, vuln_id, aliases, severity, kev, summary, cvss, status, first_seen, last_seen FROM vulnerability_finding WHERE agent_id = ? AND status = 'open'").all(a.id)) as { severity: string; kev: number; aliases: string }[])
    .map((f) => ({ ...f, kev: !!f.kev, aliases: JSON.parse(f.aliases) as string[] }))
    .sort((x, y) => Number(y.kev) - Number(x.kev) || (SEVERITY_RANK[y.severity] ?? 0) - (SEVERITY_RANK[x.severity] ?? 0));
  return bom ? { id: bom.id, sha256: bom.sha256, created_at: bom.created_at, created_by: bom.created_by, scanned_at: bom.scanned_at, cyclonedx: JSON.parse(bom.bom) as CycloneDx, findings } : { id: null, findings };
}

/** Nightly: rescan every agent's latest AIBOM; build one for sealed agents that have none. */
export async function nightly(system: Principal) {
  const agents = (await db.prepare("SELECT a.id, (SELECT b.id FROM aibom b WHERE b.agent_id = a.id ORDER BY b.created_at DESC LIMIT 1) AS bom FROM agent a WHERE a.status != 'retired'").all()) as { id: string; bom: string | null }[];
  let done = 0;
  for (const a of agents) {
    try {
      if (a.bom) await scanAibom(a.bom);
      else if ((await db.prepare("SELECT 1 FROM certificate WHERE agent_id = ? AND status = 'active'").get(a.id))) await generate(a.id, {}, system);
      else continue;
      done++;
    } catch (e) {
      console.error(`[control] AIBOM refresh for ${a.id} failed: ${(e as Error).message}`);
    }
  }
  return { refreshed: done };
}
