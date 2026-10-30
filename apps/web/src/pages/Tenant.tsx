import { Card, KV, Mono, PageHeader, Pill } from '../components/ui';
import { useApi } from '../lib/api';
import { ROLE_LABEL, useMe } from '../lib/auth';
import { ago } from '../lib/format';

export function Tenant() {
  const me = useMe();
  const { data: gws } = useApi<any>('/gateways');
  return (
    <>
      <PageHeader title="Tenant & access" subtitle="Sign-in is single sign-on only. IdP groups map to Signet roles; roles are bundles of permissions (BP 14.2)." />
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
              ['Deployment', 'dev · single binary profile · SQLite'],
              ['Session', 'HttpOnly cookie · 30 min idle · 12 h absolute'],
            ]}
          />
        </Card>
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
