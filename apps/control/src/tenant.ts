import { env, newId, type CatalogueModel } from '@signet/core';
import { db, nowIso } from './db';
import { DEFAULT_GROUP_ROLES, type Role } from './rbac';

export interface TenantSettings {
  residency: string[];
  catalogue: CatalogueModel[];
  group_roles: Record<string, Role>;
  require_mfa: boolean;
  baseline: { max_input_tokens: number; max_cost_per_request_usd: number }; // RB-BL-03, RB-BL-04
}

// The one cloud LLM (Rulebook v0.2, D-17): gpt-oss-120b on Ollama's cloud. Region and price stay
// unverified until the provider terms record is completed (RB-PROV-03).
const defaultSettings = (): TenantSettings => ({
  residency: ['any'],
  catalogue: [
    {
      model: env('SIGNET_LLM_MODEL', 'gpt-oss:120b-cloud'),
      upstream_model: env('SIGNET_LLM_UPSTREAM_MODEL', 'gpt-oss:120b'),
      family: 'gptoss',
      region: 'unverified',
      code_approved: true,
      price_per_1k_usd: { in: 0, out: 0 },
    },
  ],
  group_roles: DEFAULT_GROUP_ROLES,
  // MFA is enforced at the IdP; the dev realm has no authenticator enrolled, so dev does not require it.
  require_mfa: env('SIGNET_REQUIRE_MFA', 'false') === 'true',
  baseline: { max_input_tokens: 32_000, max_cost_per_request_usd: 5 },
});

// Phase 1 runs a single tenant; multi-tenancy arrives with the SaaS cells (Phase 4).
function ensureTenant() {
  const row = db.prepare('SELECT id, name, settings FROM tenant LIMIT 1').get() as { id: string; name: string; settings: string } | undefined;
  if (row) return { id: row.id, name: row.name, settings: { ...defaultSettings(), ...(JSON.parse(row.settings) as Partial<TenantSettings>) } };
  const t = { id: newId('tnt'), name: env('SIGNET_TENANT_NAME', 'Northwind Financial (dev)'), settings: defaultSettings() };
  db.prepare('INSERT INTO tenant (id, name, settings, created_at) VALUES (?, ?, ?, ?)').run(t.id, t.name, JSON.stringify(t.settings), nowIso());
  return t;
}

export const tenant = ensureTenant();
