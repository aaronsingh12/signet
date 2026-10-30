import { Card, Empty, Mono, PageHeader, Pill, Stat } from '../components/ui';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';

// Discovery Inbox (Console UI & UX p.9). Phase 1 source: the Key Sweep CLI (repos, CI files, env
// files). Findings carry a fingerprint, never the key; storing the same key in the broker resolves them.
export function Discovery() {
  const can = useCan();
  const { data, reload } = useApi<any>('/discovered-assets');
  const kpi = data?.kpi;
  const resolve = async (id: string, status: string) => {
    const note = prompt(`Note for marking this finding ${status}`) ?? '';
    await api(`/discovered-assets/${id}/resolve`, { method: 'POST', body: { status, note } });
    void reload();
  };
  return (
    <>
      <PageHeader title="Discovery Inbox" subtitle="Credentials and agents found outside Signet. Move keys behind the Secrets Broker so agents become keyless, or block them." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Unmanaged keys open" value={kpi?.unmanaged_keys_open ?? '—'} hint={`${kpi?.unmanaged_keys_total ?? 0} found in total`} tone={kpi?.unmanaged_keys_open ? 'warn' : 'ok'} />
        <Stat label="Sealed agents" value={kpi?.sealed_agents ?? '—'} hint="all authenticate with workload tokens only" />
        <Stat label="Keyless agents" value={kpi ? '100%' : '—'} hint="target 100% for T1/T2 before seal" tone="ok" />
        <Stat label="Sources" value="Key Sweep" hint="platform connectors arrive in Phase 3" />
      </div>
      <Card className="mt-4" pad={false} title="Findings" action={<span className="text-xs text-ink-3">npm run keysweep -- &lt;dir&gt; --upload</span>}>
        {data?.items?.length ? (
          <table className="w-full">
            <thead><tr>{['Type', 'What we found', 'Location', 'Source', 'First seen', 'Status', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {data.items.map((f: any) => (
                <tr key={f.id}>
                  <td className="td text-xs">{f.type.replace(/_/g, ' ')}</td>
                  <td className="td"><Mono>{f.summary}</Mono><div className="text-[11px] text-ink-3">fingerprint {f.fingerprint}</div></td>
                  <td className="td mono text-xs">{f.location}</td>
                  <td className="td text-xs">{f.source}</td>
                  <td className="td text-xs">{ago(f.first_seen)}</td>
                  <td className="td"><Pill value={f.status === 'open' ? 'require_approval' : f.status === 'blocked' ? 'deny' : 'allow'} label={f.status} /></td>
                  <td className="td whitespace-nowrap">
                    {f.status === 'open' && can('discovery.write') && (
                      <>
                        <button className="mr-1 text-xs text-royal hover:underline" onClick={() => void resolve(f.id, 'migrated')}>Migrated</button>
                        <button className="mr-1 text-xs text-bad hover:underline" onClick={() => void resolve(f.id, 'blocked')}>Block</button>
                        <button className="text-xs text-ink-3 hover:underline" onClick={() => void resolve(f.id, 'dismissed')}>Dismiss</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>Nothing found yet. Run Key Sweep over your repositories and upload the findings.</Empty>
        )}
      </Card>
      <Card className="mt-4" title="Migrate a key to the broker">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-ink-2">
          <li>A platform admin stores the key in the Secrets Broker (Tools & secrets). Findings with the same fingerprint close automatically.</li>
          <li>The agent is sealed and gets a workload identity: a one-time bootstrap credential, then short-lived tokens.</li>
          <li>Point the agent's base URL at the gateway: <Mono>OPENAI_BASE_URL=http://localhost:8100/v1</Mono>.</li>
          <li>Ask the owner to rotate the original key and remove it from the repository.</li>
        </ol>
      </Card>
    </>
  );
}
