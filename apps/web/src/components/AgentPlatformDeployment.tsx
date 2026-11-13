import { useState } from 'react';
import { useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { PLATFORM_NAMES, type PlatformAccount } from './PlatformAccountForm';
import { LinkModal, type Workload } from './PlatformConnectors';
import { Card, ErrorNote } from './ui';

interface SourceLink { connection_id: string; workload_id: string; workload_name: string; agent_id: string; state: string }

/** Apply the saved source's deployment settings through the existing provider connector after approval. */
export function AgentPlatformDeployment({ agentId, onChange }: { agentId: string; onChange: () => void }) {
  const can = useCan();
  const { data, error, reload } = useApi<{ items: PlatformAccount[]; links: SourceLink[] }>(can('connectors.manage') ? '/platforms' : null);
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;
  if (!Array.isArray(data.items) || !data.items.every((item) => item && typeof item.id === 'string' && Object.hasOwn(PLATFORM_NAMES, item.platform)) || !Array.isArray(data.links) || !data.links.every((link) => link && typeof link.connection_id === 'string' && typeof link.workload_id === 'string' && typeof link.workload_name === 'string' && typeof link.agent_id === 'string' && typeof link.state === 'string')) return <ErrorNote error={new TypeError('Platform deployment response requires valid accounts and source links')} />;
  return <>{data.links.filter((link) => link.agent_id === agentId).map((link) => {
    const account = data.items.find((item) => item.id === link.connection_id);
    return account ? <SourceDeployment key={`${link.connection_id}:${link.workload_id}`} account={account} source={link} onChange={() => { void reload(); onChange(); }} /> : <ErrorNote key={link.connection_id} error={new Error(`Platform account ${link.connection_id} is disconnected. Reconnect it before deploying ${link.workload_name}.`)} />;
  })}</>;
}

function SourceDeployment({ account, source, onChange }: { account: PlatformAccount; source: SourceLink; onChange: () => void }) {
  const { data, error } = useApi<{ items: Workload[] }>(`/platforms/${account.id}/workloads`);
  const [linking, setLinking] = useState(false);
  if (data && (!Array.isArray(data.items) || !data.items.every((item) => item && typeof item.id === 'string' && typeof item.name === 'string' && typeof item.linkable === 'boolean' && (item.registered_agent_id === null || typeof item.registered_agent_id === 'string') && Array.isArray(item.env_names) && item.env_names.every((name) => typeof name === 'string') && Array.isArray(item.ai_signals) && item.ai_signals.every((signal) => signal && typeof signal.name === 'string' && ['key', 'base_url', 'model', 'platform'].includes(signal.kind))))) return <ErrorNote error={new TypeError(`Platform ${account.id} returned invalid workload deployment settings`)} />;
  const workload = data?.items.find((item) => item.id === source.workload_id);
  return <Card title={`${PLATFORM_NAMES[account.platform]} deployment`}>
    <p className="text-sm">{source.workload_name} · {source.state}</p>
    {workload?.linkable ? <><p className="mt-2 text-sm text-ink-2">After approval, apply Signet's Gateway URL and an agent credential directly through this platform. Review the variable names and restart option before applying.</p><button type="button" data-testid="agent-platform-deploy" className="btn-primary mt-3" onClick={() => setLinking(true)}>Configure and apply to platform</button></> : data && <p className="mt-2 text-sm text-ink-2">This source is registered for review and monitoring. For a vendor-hosted agent, configure its company-tool calls to use Signet. For your own code, use the connection file below; discovery alone does not route traffic.</p>}
    <ErrorNote error={error} />
    {linking && workload && <LinkModal connectionId={account.id} platform={account.platform} workload={workload} onClose={() => setLinking(false)} onDone={onChange} />}
  </Card>;
}
