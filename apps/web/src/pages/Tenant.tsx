import { Link } from 'react-router-dom';
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
              ['Database', 'MongoDB'],
              ['Session', 'HttpOnly cookie · 30 min idle · 12 h absolute'],
            ]}
          />
        </Card>
        <Card title="Gateway cost"><p className="text-sm text-ink-2">Model pricing and per-agent token usage are managed in Gateway cost.</p><Link className="btn-ghost mt-3" to="/settings/gateway-cost">Manage gateway cost</Link></Card>
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
