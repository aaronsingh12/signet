import { useState } from 'react';
import { Link, Navigate, useLocation, useSearchParams } from 'react-router-dom';
import { Card, ErrorNote, PageHeader, Tabs } from '../components/ui';
import { ApiError, api } from '../lib/api';
import { useCan } from '../lib/auth';
import { Controls } from './Controls';
import { Ledger } from './Ledger';
import { LiveTraffic } from './LiveTraffic';

// The menu's grouping pages: Activity, Reports and the Settings directory.

// Old addresses still arrive from stored notifications and bookmarks.
export function Moved({ to }: { to: string }) {
  const { search } = useLocation();
  const [path, query] = to.split('?');
  const merged = new URLSearchParams(search);
  new URLSearchParams(query).forEach((value, key) => merged.set(key, value));
  const q = merged.toString();
  return <Navigate to={`${path}${q ? `?${q}` : ''}`} replace />;
}

export function Activity() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') ?? (params.get('record') || params.get('agent') ? 'history' : 'live');
  return <>
    <Tabs active={tab} onChange={(id) => setParams({ tab: id })} tabs={[{ id: 'live', label: 'Live' }, { id: 'history', label: 'History' }]} />
    {tab === 'live' ? <LiveTraffic /> : <Ledger />}
  </>;
}

export function Reports() {
  const can = useCan();
  const [result, setResult] = useState<{ ok: boolean; count?: number; roots_valid?: boolean; broken_at?: number } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const check = async () => {
    setBusy(true);
    try {
      setResult(await api('/ledger/verify', { method: 'POST', body: {} }));
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const intact = result?.ok && result.roots_valid !== false;
  return <>
    <PageHeader title="Reports" subtitle="Proof for auditors, regulators and your board." actions={can('evidence.export') && <a className="btn-primary" href="/api/v1/ledger/export">Download evidence package</a>} />
    {can('ledger.verify') && <Card className="mb-5"><div className="flex flex-wrap items-center justify-between gap-4"><div><h2 className="font-semibold">Is the record intact?</h2><p className="mt-1 text-sm text-ink-2" data-testid="integrity-result">{!result ? 'Check that no activity record has been changed or removed.' : intact ? `Yes. Nothing has been altered${result.count !== undefined ? ` (${result.count.toLocaleString()} records checked)` : ''}.` : 'No. A record does not match. Contact your security team and keep the evidence.'}</p></div><button className="btn-ghost" data-testid="integrity-check" disabled={busy} onClick={() => void check()}>{busy ? 'Checking…' : 'Check now'}</button></div><div className="mt-2"><ErrorNote error={error} /></div></Card>}
    {can('compliance.read') ? <Controls /> : <Card><p className="text-sm text-ink-2">Compliance results are available to your risk, security and audit teams.</p></Card>}
  </>;
}

const SETTINGS = [
  { to: '/settings/people', title: 'People & roles', text: 'Who can add, approve and audit', perm: 'tenant.read' },
  { to: '/settings/apps', title: 'Connected apps & keys', text: 'Apps agents can use and their stored credentials', perm: 'agents.read' },
  { to: '/settings/accounts', title: 'Connected accounts', text: 'Vercel account sign-in and service integrations', perm: 'connectors.manage' },
  { to: '/settings/systems', title: 'Company systems', text: 'ServiceNow and connected AI platforms', perm: 'compliance.read' },
  { to: '/settings/rules', title: 'Safety rules', text: 'Detectors, company-wide defaults and limits', perm: 'agents.read' },
  { to: '/settings/agent-defaults', title: 'Agent list', text: 'Manage and permanently remove agents', perm: 'agents.read' },
  { to: '/settings/discovery', title: 'Finding hidden AI', text: 'Key sweeps, log uploads and unmanaged AI use', perm: 'discovery.read' },
  { to: '/settings/safety', title: 'Safety center', text: 'Stop history, emergency stops and gateway health', perm: 'ledger.read' },
];

export function Settings() {
  const can = useCan();
  return <>
    <PageHeader title="Settings" subtitle="You rarely need these. Everything is grouped by what you're trying to do." />
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{SETTINGS.filter((s) => can(s.perm) || can('tenant.admin')).map((s) => <Link key={s.to} to={s.to} className="card settings-tile"><h2>{s.title}</h2><p>{s.text}</p></Link>)}</div>
  </>;
}
