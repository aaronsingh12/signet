import { ExternalLink, Link2, Plug, Rocket, Unplug } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { PlatformConnectors } from '../components/PlatformConnectors';

interface VercelConnection {
  configured: boolean;
  connected: boolean;
  email: string | null;
  name: string | null;
  expires_at: string | null;
}

// Integration catalog only. Connection credentials and provider APIs are added with each integration.
export function Plugins() {
  const canManage = useCan()('tenant.admin');
  const { data: vercel, error, reload } = useApi<VercelConnection>(canManage ? '/plugins/vercel' : null);
  const disconnect = async () => {
    await api('/plugins/vercel/disconnect', { method: 'POST' });
    await reload();
  };
  return (
    <>
      <PageHeader title="Connections" subtitle="Connect your deployment platforms and services to bring AI agents into Signet." />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <div className="flex items-start gap-3">
            <div className="rounded-md bg-black px-2 py-1.5 text-sm font-semibold text-white" aria-hidden="true">▲</div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-semibold">Vercel</h2>
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${vercel?.connected ? 'bg-ok-50 text-ok' : 'bg-slate-100 text-ink-2'}`}>{vercel?.connected ? 'Connected' : 'Not connected'}</span>
              </div>
              <p className="mt-1 text-sm text-ink-2">Sign in with Vercel to identify your account. To connect projects to Signet, use the access-token connector below.</p>
              {canManage && <ErrorNote error={error} />}
              {!canManage ? (
                <p className="mt-3 text-xs text-ink-3">A Tenant Admin can connect Vercel for this tenant.</p>
              ) : vercel?.connected ? (
                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <span className="text-xs text-ink-3">Connected as {vercel.name ?? vercel.email ?? 'Vercel user'}</span>
                  <button className="btn-ghost inline-flex items-center gap-1.5" onClick={() => void disconnect()}><Unplug size={14} /> Disconnect</button>
                </div>
              ) : vercel?.configured ? (
                <button className="btn-primary mt-3 inline-flex items-center gap-2" onClick={() => location.assign('/api/v1/plugins/vercel/connect')}>
                  <Link2 size={15} /> Connect Vercel
                </button>
              ) : (
                <p className="mt-3 text-xs text-warn">Add the Vercel App client ID and secret to Signet server configuration to enable connection.</p>
              )}
            </div>
          </div>
        </Card>
        <Card>
          <div className="flex items-start gap-3">
            <div className="rounded-md bg-royal-50 p-2 text-royal" aria-hidden="true"><Plug size={18} /></div>
            <div>
              <h2 className="text-base font-semibold">More integrations</h2>
              <p className="mt-1 text-sm text-ink-2">Additional providers will appear here as they become available. No existing onboarding flow is replaced.</p>
            </div>
          </div>
        </Card>
      </div>
      {canManage && <PlatformConnectors />}
      <Card className="mt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">Manual onboarding</h2>
            <p className="mt-1 text-sm text-ink-2">Create and govern an agent directly in Signet, as before.</p>
          </div>
          <Link className="btn-primary inline-flex items-center gap-2" to="/agents/new">
            <Rocket size={15} /> Propose agent <ExternalLink size={14} />
          </Link>
        </div>
      </Card>
    </>
  );
}
