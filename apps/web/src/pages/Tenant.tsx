import { useState } from 'react';
import { Card, KV, Mono, PageHeader, Pill } from '../components/ui';
import { api, useApi } from '../lib/api';
import { ROLE_LABEL, useMe } from '../lib/auth';
import { ago } from '../lib/format';

// SCIM provisioning (BP 11.4): the identity provider keeps people and groups in step; leavers' agents
// are flagged until the sponsor names a new owner.
function Provisioning({ canEdit }: { canEdit: boolean }) {
  const { data, reload } = useApi<any>('/scim/status');
  const [token, setToken] = useState<string | null>(null);
  if (!data) return null;
  const url = `${window.location.origin}${data.base_path}`;
  return (
    <Card title="User provisioning (SCIM)">
      <KV
        rows={[
          ['SCIM base URL', <Mono key="u">{url}</Mono>],
          ['Token', data.token ? `created ${ago(data.token.created_at)} by ${data.token.created_by}` : 'not created yet'],
          ['People', `${data.active_users} active of ${data.users}`],
          ['Groups', String(data.groups)],
        ]}
      />
      {token && <div className="mt-2 rounded-md bg-amber-50 p-2 text-xs">Copy this token into your identity provider now; it is not shown again: <Mono>{token}</Mono></div>}
      {canEdit && <button className="btn-ghost mt-2" onClick={() => { if (!data.token || window.confirm('A new token stops the current one. Continue?')) void api<any>('/scim/token', { method: 'POST' }).then((r) => { setToken(r.token); void reload(); }); }}>{data.token ? 'Replace token' : 'Create token'}</button>}
      {data.agents_without_owner.length > 0 && (
        <div className="mt-3 text-sm">
          <div className="font-medium">Agents whose owner left</div>
          <ul className="mt-1 space-y-1 text-xs">
            {data.agents_without_owner.map((a: any) => <li key={a.id}><a className="hover:underline" href={`/agents/${a.id}`}>{a.handle}</a> · owner {a.owner} · sponsor {a.sponsor} · name a new owner by {a.reassign_by.slice(0, 10)}</li>)}
          </ul>
        </div>
      )}
    </Card>
  );
}

export function Tenant() {
  const me = useMe();
  const { data: gws } = useApi<any>('/gateways');
  return (
    <>
      <PageHeader title="Workspace & access" subtitle="See your workspace, team permissions and connected safety gateways." />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="You">
          <KV
            rows={[
              ['Identity', <Mono key="i">{me.principal.id}</Mono>],
              ['Roles', me.principal.roles.map((r) => ROLE_LABEL[r] ?? r).join(', ') || 'none'],
              ['MFA at IdP', me.principal.mfa ? 'yes' : 'not asserted by the dev realm'],
              ['Permissions', <span key="p" className="text-xs">{me.principal.permissions.join(', ')}</span>],
            ]}
          />
        </Card>
        <Card title="Tenant">
          <KV
            rows={[
              ['Name', me.tenant.name],
              ['ID', <Mono key="t">{me.tenant.id}</Mono>],
              ['Identity provider', 'Keycloak (OIDC, embedded for dev and air-gapped installs)'],
              ['Database', 'PostgreSQL'],
              ['Session', 'HttpOnly cookie · 30 min idle · 12 h absolute'],
            ]}
          />
        </Card>
        <ModelPricing canEdit={me.principal.permissions.includes('tenant.admin')} />
        <Provisioning canEdit={me.principal.permissions.includes('tenant.admin')} />
        <Card title="Group to role mapping" pad={false}>
          <table className="w-full">
            <tbody>
              {Object.entries(ROLE_LABEL).map(([role, label]) => (
                <tr key={role}>
                  <td className="td mono text-xs">signet-{role.replace(/_/g, '-').replace('officer', 'officers').replace('owner', 'owners').replace('admin', 'admins').replace('builder', 'builders').replace('approver', 'approvers').replace('auditor', 'auditors').replace('viewer', 'viewers').replace('governance-board', 'governance-board')}</td>
                  <td className="td">{label}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title="Gateway nodes" pad={false}>
          <table className="w-full">
            <thead><tr>{['Node', 'Address', 'Heartbeat', 'Bundle', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {(gws?.items ?? []).map((g: any) => {
                const healthy = Date.now() - Date.parse(g.last_seen) < 30_000;
                return (
                  <tr key={g.id}>
                    <td className="td mono">{g.id}</td>
                    <td className="td mono text-xs">{g.url}</td>
                    <td className="td text-xs">{ago(g.last_seen)}</td>
                    <td className="td mono text-xs">{g.bundle_version}</td>
                    <td className="td"><Pill value={healthy ? 'allow' : 'deny'} label={healthy ? 'healthy' : 'stale'} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}

type Model = { model: string; price_per_1k_usd: { in: number; out: number } };

// Prices drive recorded cost, the daily cost budget and the per-request cost ceiling. A price of 0
// means cost is not tracked; existing records keep the price that applied when they were made.
function ModelPricing({ canEdit }: { canEdit: boolean }) {
  const { data, reload } = useApi<{ catalogue: Model[] }>('/catalogue');
  const [draft, setDraft] = useState<Record<string, { in: string; out: string }>>({});
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const save = async (m: Model) => {
    const d = draft[m.model] ?? { in: String(m.price_per_1k_usd.in), out: String(m.price_per_1k_usd.out) };
    try {
      await api(`/catalogue/${encodeURIComponent(m.model)}/price`, { method: 'PUT', body: { in: Number(d.in), out: Number(d.out) } });
      setMsg({ ok: true, text: `Saved. New requests to ${m.model} are costed at this price.` });
      await reload();
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    }
  };
  return (
    <Card title="Model pricing">
      <p className="mb-3 text-xs text-slate-500">USD per 1,000 tokens. Used for cost tracking and daily cost budgets. At 0, cost shows as $0.00 and cost budgets never trigger.</p>
      {(data?.catalogue ?? []).map((m) => {
        const d = draft[m.model] ?? { in: String(m.price_per_1k_usd.in), out: String(m.price_per_1k_usd.out) };
        const set = (k: 'in' | 'out', v: string) => setDraft({ ...draft, [m.model]: { ...d, [k]: v } });
        return (
          <div key={m.model} className="mb-2 grid items-end gap-2 sm:grid-cols-[1fr_8rem_8rem_auto]">
            <div className="mono text-sm">{m.model}</div>
            <label className="text-xs text-slate-500">Input<input className="input mt-1" type="number" min="0" step="0.0001" disabled={!canEdit} value={d.in} onChange={(e) => set('in', e.target.value)} /></label>
            <label className="text-xs text-slate-500">Output<input className="input mt-1" type="number" min="0" step="0.0001" disabled={!canEdit} value={d.out} onChange={(e) => set('out', e.target.value)} /></label>
            {canEdit && <button className="btn-primary" onClick={() => void save(m)}>Save</button>}
          </div>
        );
      })}
      {msg && <p className={`mt-2 text-xs ${msg.ok ? 'text-emerald-700' : 'text-red-600'}`}>{msg.text}</p>}
    </Card>
  );
}
