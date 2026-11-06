import { env, newId, type CatalogueModel } from '@signet/core';
import { db, nowIso } from './db';
import { DEFAULT_GROUP_ROLES, type Role } from './rbac';

export interface TenantSettings {
  residency: string[];
  catalogue: CatalogueModel[];
  group_roles: Record<string, Role>;
  require_mfa: boolean;
  baseline: { max_input_tokens: number; max_cost_per_request_usd: number }; // RB-BL-03, RB-BL-04
  // Runtime approver groups named in seals (hitl[].approver_group) and tenant rules, mapped to roles.
  approver_groups: Record<string, { roles: Role[]; count?: number; owner?: boolean }>;
  hitl_wait_seconds: number; // BP 5.2 step 10: hold the connection up to this long (default 120 s)
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
  approver_groups: {
    'ops-supervisors': { roles: ['approver', 'security_officer'] },
    'owner-approvers': { roles: ['approver', 'security_officer'], owner: true },
    'security-approvers': { roles: ['security_officer'] },
    'dual-control': { roles: ['approver', 'security_officer', 'risk_officer'], count: 2 },
  },
  hitl_wait_seconds: Number(env('SIGNET_HITL_WAIT_SECONDS', '120')),
});

// Phase 1 runs a single tenant; multi-tenancy arrives with the SaaS cells (Phase 4).
async function ensureTenant() {
  const row = (await db.prepare('SELECT id, name, settings FROM tenant LIMIT 1').get()) as { id: string; name: string; settings: string } | undefined;
  if (row) {
    const name = env('SIGNET_TENANT_NAME', row.name);
    if (name !== row.name) (await db.prepare('UPDATE tenant SET name = ? WHERE id = ?').run(name, row.id));
    return { id: row.id, name, settings: { ...defaultSettings(), ...(JSON.parse(row.settings) as Partial<TenantSettings>) } };
  }
  const t = { id: newId('tnt'), name: env('SIGNET_TENANT_NAME', 'Signet'), settings: defaultSettings() };
  (await db.prepare('INSERT INTO tenant (id, name, settings, created_at) VALUES (?, ?, ?, ?)').run(t.id, t.name, JSON.stringify(t.settings), nowIso()));
  return t;
}

export const tenant = (await ensureTenant());

/** Re-read settings saved by another control instance (Vercel runs several), keeping this object's identity. */
export async function reloadSettings(): Promise<TenantSettings> {
  const row = (await db.prepare('SELECT settings FROM tenant WHERE id = ?').get(tenant.id)) as { settings: string } | undefined;
  if (row) Object.assign(tenant.settings, { ...defaultSettings(), ...(JSON.parse(row.settings) as Partial<TenantSettings>) });
  return tenant.settings;
}

/** Adds or re-points an agent's own LLM. The tenant's default LLM cannot be overwritten this way. */
export async function setAgentModel(model: string, upstream: NonNullable<CatalogueModel['upstream']>): Promise<CatalogueModel> {
  await reloadSettings();
  let entry = tenant.settings.catalogue.find((c) => c.model === model);
  if (entry && !entry.upstream) throw new Error(`${model} is the default LLM`);
  if (entry) entry.upstream = upstream;
  else {
    // Providers often report the name without its tag (beam:cloud answers as beam).
    entry = { model, upstream_model: model.split(':')[0]!, family: model.split(':')[0]!, region: 'unverified', code_approved: false, price_per_1k_usd: { in: 0, out: 0 }, upstream };
    tenant.settings.catalogue.push(entry);
  }
  (await db.prepare('UPDATE tenant SET settings = ? WHERE id = ?').run(JSON.stringify(tenant.settings), tenant.id));
  return entry;
}

/** Price per 1,000 tokens for one catalogue model; costs, daily budgets and the per-request cost ceiling use it. */
export async function setModelPrice(model: string, price: { in: number; out: number }): Promise<CatalogueModel> {
  await reloadSettings();
  const entry = tenant.settings.catalogue.find((c) => c.model === model);
  if (!entry) return Promise.reject(new Error(`unknown model ${model}`));
  entry.price_per_1k_usd = { in: price.in, out: price.out };
  (await db.prepare('UPDATE tenant SET settings = ? WHERE id = ?').run(JSON.stringify(tenant.settings), tenant.id));
  return entry;
}
