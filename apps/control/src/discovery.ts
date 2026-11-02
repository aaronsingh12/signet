import { newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

// Discovery Inbox (BP 1B.3 Key Sweep, C10). Phase 1 ingests Key Sweep findings from the `signet
// keysweep` CLI (repos, CI files, env files); platform API connectors are Phase 3. Findings carry a
// fingerprint of the key, never the key itself.

export interface FindingInput {
  type: 'unmanaged_key' | 'direct_traffic' | 'unregistered_agent';
  summary: string;
  location: string;
  fingerprint: string;
}

export function ingest(source: string, items: FindingInput[], p: Principal) {
  if (!source || !Array.isArray(items)) throw invalid('source and items[] are required');
  let added = 0;
  tx(() => {
    for (const f of items) {
      if (!/^[0-9a-f]{16}$/.test(f.fingerprint ?? '')) throw invalid('fingerprint must be 16 hex characters (sha256 prefix)');
      const existing = db.prepare('SELECT id FROM discovered_asset WHERE tenant_id = ? AND fingerprint = ? AND location = ?').get(tenant.id, f.fingerprint, f.location) as { id: string } | undefined;
      if (existing) db.prepare('UPDATE discovered_asset SET last_seen = ? WHERE id = ?').run(nowIso(), existing.id);
      else {
        // Already in the broker under the same fingerprint: the copy in code is a leftover to remove.
        const brokered = db.prepare('SELECT name FROM secret WHERE tenant_id = ? AND fingerprint = ?').get(tenant.id, f.fingerprint) as { name: string } | undefined;
        db.prepare('INSERT INTO discovered_asset (id, tenant_id, source, type, summary, location, fingerprint, status, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
          newId('fnd'), tenant.id, source, f.type, brokered ? `${f.summary} (brokered as ${brokered.name}; remove this copy)` : f.summary, f.location, f.fingerprint, 'open', nowIso(), nowIso(),
        );
        added++;
      }
    }
    if (source.startsWith('keysweep')) touchSource('keysweep', items.length);
    ledger.append({ kind: 'admin', data: { event: 'discovery.scan_ingested', source, findings: items.length, new: added, actor: p.id } });
  });
  return { received: items.length, new: added };
}

export function list(status?: string) {
  return status
    ? db.prepare('SELECT * FROM discovered_asset WHERE tenant_id = ? AND status = ? ORDER BY last_seen DESC').all(tenant.id, status)
    : db.prepare('SELECT * FROM discovered_asset WHERE tenant_id = ? ORDER BY status, last_seen DESC').all(tenant.id);
}

export function resolve(id: string, status: 'migrated' | 'blocked' | 'dismissed', note: string, p: Principal) {
  const row = db.prepare('SELECT * FROM discovered_asset WHERE tenant_id = ? AND id = ?').get(tenant.id, id);
  if (!row) throw notFound(`finding ${id}`);
  db.prepare('UPDATE discovered_asset SET status = ?, resolved_by = ? WHERE id = ?').run(status, p.id, id);
  ledger.append({ kind: 'admin', data: { event: `discovery.${status}`, finding_id: id, note, actor: p.id } });
  return db.prepare('SELECT * FROM discovered_asset WHERE id = ?').get(id);
}

// Findings whose fingerprint now lives in the broker are marked migrated automatically.
export function reconcileWithBroker() {
  return db.prepare("UPDATE discovered_asset SET status = 'migrated', resolved_by = 'broker-match' WHERE status = 'open' AND fingerprint IN (SELECT fingerprint FROM secret)").run().changes;
}

export function keylessKpi() {
  const open = (db.prepare("SELECT COUNT(*) AS n FROM discovered_asset WHERE tenant_id = ? AND type = 'unmanaged_key' AND status = 'open'").get(tenant.id) as { n: number }).n;
  const total = (db.prepare("SELECT COUNT(*) AS n FROM discovered_asset WHERE tenant_id = ? AND type = 'unmanaged_key'").get(tenant.id) as { n: number }).n;
  const sealed = (db.prepare("SELECT COUNT(*) AS n FROM agent WHERE tenant_id = ? AND status IN ('sealed', 'quarantined')").get(tenant.id) as { n: number }).n;
  // Keyless is counted only where the SDK or sidecar reported the runtime: the latest report per agent
  // decides. Sealed agents that never reported are unverified, not assumed keyless.
  const latest = db.prepare("SELECT d.agent_id, d.bypass_risk FROM agent_diagnostic d JOIN agent a ON a.id = d.agent_id WHERE a.tenant_id = ? AND a.status IN ('sealed', 'quarantined') AND d.reported_at = (SELECT MAX(reported_at) FROM agent_diagnostic x WHERE x.agent_id = d.agent_id)").all(tenant.id) as { agent_id: string; bypass_risk: number }[];
  const verified = latest.filter((r) => !r.bypass_risk).length;
  const risky = latest.filter((r) => r.bypass_risk).length;
  return { sealed_agents: sealed, keyless_verified: verified, bypass_risk_agents: risky, unverified_agents: Math.max(0, sealed - latest.length), unmanaged_keys_open: open, unmanaged_keys_total: total };
}

// --- Discovery sources --------------------------------------------------------------------------
// Each source reports when it last delivered data. A source that never delivered shows as not
// connected; nothing is filled in on its behalf.

const SOURCES = [
  { id: 'keysweep', kind: 'code_scan', label: 'Key Sweep (signet keysweep CLI: repos, CI files, env files)' },
  { id: 'network-logs', kind: 'network', label: 'Network logs (proxy, DNS or firewall exports)' },
  { id: 'saas-audit', kind: 'saas', label: 'SaaS audit logs (e.g. Microsoft 365, Google Workspace, Okta app usage)' },
  { id: 'sdk-diagnostics', kind: 'runtime', label: 'Signet SDK and sidecar start-up diagnostics' },
];
for (const s of SOURCES) db.prepare('INSERT OR IGNORE INTO discovery_source (id, kind, label) VALUES (?, ?, ?)').run(s.id, s.kind, s.label);

export const sources = () =>
  (db.prepare('SELECT * FROM discovery_source ORDER BY id').all() as { id: string; last_ingest_at: string | null }[]).map((s) => ({ ...s, connected: !!s.last_ingest_at }));

function touchSource(id: string, count: number) {
  db.prepare('UPDATE discovery_source SET last_ingest_at = ?, last_count = ?, total = total + ? WHERE id = ?').run(nowIso(), count, count, id);
}

// Public endpoints of AI services. Traffic from a host to one of these that does not come from a Signet
// gateway is an AI integration Signet does not govern.
export const AI_PROVIDERS: { domain: RegExp; provider: string; kind: 'api' | 'app' }[] = [
  { domain: /(^|\.)api\.openai\.com$/, provider: 'OpenAI API', kind: 'api' },
  { domain: /(^|\.)openai\.azure\.com$/, provider: 'Azure OpenAI', kind: 'api' },
  { domain: /(^|\.)api\.anthropic\.com$/, provider: 'Anthropic API', kind: 'api' },
  { domain: /(^|\.)generativelanguage\.googleapis\.com$/, provider: 'Google Gemini API', kind: 'api' },
  { domain: /(^|\.)aiplatform\.googleapis\.com$/, provider: 'Google Vertex AI', kind: 'api' },
  { domain: /^bedrock(-runtime|-agent-runtime)?\.[a-z0-9-]+\.amazonaws\.com$/, provider: 'Amazon Bedrock', kind: 'api' },
  { domain: /(^|\.)ollama\.com$/, provider: 'Ollama cloud', kind: 'api' },
  { domain: /(^|\.)api\.mistral\.ai$/, provider: 'Mistral API', kind: 'api' },
  { domain: /(^|\.)api\.cohere\.(ai|com)$/, provider: 'Cohere API', kind: 'api' },
  { domain: /(^|\.)api\.groq\.com$/, provider: 'Groq API', kind: 'api' },
  { domain: /(^|\.)api\.together\.(xyz|ai)$/, provider: 'Together AI', kind: 'api' },
  { domain: /(^|\.)openrouter\.ai$/, provider: 'OpenRouter', kind: 'api' },
  { domain: /(^|\.)api\.deepseek\.com$/, provider: 'DeepSeek API', kind: 'api' },
  { domain: /(^|\.)api\.perplexity\.ai$/, provider: 'Perplexity API', kind: 'api' },
  { domain: /(^|\.)api-inference\.huggingface\.co$|(^|\.)router\.huggingface\.co$/, provider: 'Hugging Face inference', kind: 'api' },
  { domain: /(^|\.)api\.x\.ai$/, provider: 'xAI API', kind: 'api' },
  { domain: /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/, provider: 'ChatGPT (app)', kind: 'app' },
  { domain: /(^|\.)claude\.ai$/, provider: 'Claude (app)', kind: 'app' },
  { domain: /(^|\.)gemini\.google\.com$/, provider: 'Gemini (app)', kind: 'app' },
  { domain: /(^|\.)copilot\.microsoft\.com$/, provider: 'Microsoft Copilot (app)', kind: 'app' },
  { domain: /(^|\.)perplexity\.ai$/, provider: 'Perplexity (app)', kind: 'app' },
];

export function matchProvider(host: string) {
  const h = host.toLowerCase().replace(/\.$/, '');
  return AI_PROVIDERS.find((p) => p.domain.test(h)) ?? null;
}

export interface LogRecord {
  ts?: string;
  host?: string; // destination host name
  url?: string; // or a full URL
  src?: string; // source host or IP
  user?: string; // user, if the log has one
}

// Network or SaaS log export → findings for AI traffic that bypasses Signet. Hosts listed in
// gateway_hosts (the Signet gateway nodes, egress NAT addresses) are expected and skipped.
export function ingestLogs(sourceId: 'network-logs' | 'saas-audit', records: LogRecord[], p: Principal, gatewayHosts: string[] = []) {
  if (!Array.isArray(records)) throw invalid('records[] is required');
  if (records.length > 50_000) throw invalid('at most 50,000 records per upload');
  const skip = new Set(gatewayHosts.map((h) => h.toLowerCase()));
  const groups = new Map<string, { src: string; user: string | null; provider: string; kind: string; domain: string; count: number; first: string; last: string }>();
  let matched = 0;
  for (const r of records) {
    let host = typeof r.host === 'string' ? r.host : '';
    if (!host && typeof r.url === 'string') {
      try {
        host = new URL(r.url).hostname;
      } catch {
        continue;
      }
    }
    const m = host ? matchProvider(host) : null;
    if (!m) continue;
    const src = String(r.src ?? r.user ?? 'unknown').slice(0, 120);
    if (skip.has(src.toLowerCase())) continue;
    matched++;
    const ts = typeof r.ts === 'string' && !Number.isNaN(Date.parse(r.ts)) ? new Date(r.ts).toISOString() : nowIso();
    const key = `${src}|${m.provider}`;
    const g = groups.get(key) ?? { src, user: r.user ? String(r.user).slice(0, 120) : null, provider: m.provider, kind: m.kind, domain: host.toLowerCase(), count: 0, first: ts, last: ts };
    g.count++;
    if (ts < g.first) g.first = ts;
    if (ts > g.last) g.last = ts;
    groups.set(key, g);
  }
  let added = 0;
  tx(() => {
    for (const g of groups.values()) {
      const fingerprint = sha256(`${g.src}|${g.provider}`).slice(0, 16);
      const location = `${g.src} → ${g.domain}`;
      const evidence = JSON.stringify({ source: sourceId, provider: g.provider, kind: g.kind, domain: g.domain, requests: g.count, first_seen: g.first, last_seen: g.last });
      const existing = db.prepare('SELECT id FROM discovered_asset WHERE tenant_id = ? AND fingerprint = ? AND location = ?').get(tenant.id, fingerprint, location) as { id: string } | undefined;
      if (existing) db.prepare('UPDATE discovered_asset SET last_seen = ?, evidence = ? WHERE id = ?').run(g.last, evidence, existing.id);
      else {
        db.prepare('INSERT INTO discovered_asset (id, tenant_id, source, type, summary, location, fingerprint, status, first_seen, last_seen, evidence, owner_hint) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
          newId('fnd'), tenant.id, sourceId, g.kind === 'app' ? 'ai_app_usage' : 'direct_traffic',
          `${g.kind === 'app' ? 'AI app used' : 'Direct AI API traffic, not through Signet'}: ${g.provider} from ${g.src} (${g.count} request${g.count === 1 ? '' : 's'})`,
          location, fingerprint, 'open', g.first, g.last, evidence, g.user ?? g.src,
        );
        added++;
      }
    }
    touchSource(sourceId, records.length);
    ledger.append({ kind: 'admin', data: { event: 'discovery.logs_ingested', source: sourceId, records: records.length, ai_matches: matched, new_findings: added, actor: p.id } });
  });
  return { received: records.length, ai_matches: matched, groups: groups.size, new: added };
}
