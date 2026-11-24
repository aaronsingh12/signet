import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Cloud, RefreshCw } from 'lucide-react';
import { Card, ErrorNote, Modal } from './ui';
import { ConnectionIcon } from './ConnectionIcon';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';

// Amazon Bedrock agents: connect an AWS account, list its AgentCore and Classic agents, link one to Signet.
// Linking registers the agent's identity only; review, approval and gateway setup follow as for any agent.

interface AwsConnectionView {
  id: string; label: string; account_id: string | null; regions: string; status: string; status_detail: string | null; created_at: string; linked_agents: number;
}
interface AwsAgent { ref: string; kind: string; kind_label: string; id: string; name: string; region: string; status: string; active: boolean }
interface LinkedAgent { agent_id: string; agent_ref: string; kind_label: string; connection_id: string; name: string; handle: string; purpose: string; gateway_enforcement: boolean }

const BASE = '/plugins/aws';
const errorOf = (failure: unknown, fallback: string): Error => failure instanceof Error ? failure : new Error(fallback);

export const AWS_READER_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:ListHarnesses",
        "bedrock-agentcore:ListAgentRuntimes",
        "bedrock:ListAgents",
        "bedrock:GetAgent",
        "lambda:ListFunctions"
      ],
      "Resource": "*"
    }
  ]
}`;

export function AwsConnection() {
  const canManage = useCan()('tenant.admin');
  const { data, error, loading, reload } = useApi<{ items: AwsConnectionView[] }>(canManage ? BASE : null);
  const [adding, setAdding] = useState(false);
  return <div className="space-y-4">
    <Card>
      <h2 className="text-base font-semibold">Amazon Bedrock connections and AI agents</h2>
      {canManage ? <button type="button" data-testid="aws-add-connection" className="btn-primary mt-3" onClick={() => setAdding(true)}>Add Amazon Bedrock Agents</button>
        : <p className="mt-2 text-sm text-ink-3">A Tenant Admin can manage these connections.</p>}
      {loading && <p role="status">Loading connections…</p>}
      <ErrorNote error={error} />
      {data && !data.items.length && <p className="mt-3 text-sm text-ink-3">No Amazon Bedrock connections saved yet.</p>}
    </Card>
    <div className="grid grid-cols-[repeat(auto-fill,minmax(180px,220px))] gap-4">
      {data?.items.map(connection => <SavedAwsConnection key={connection.id} connection={connection} onChanged={() => { void reload(); }} />)}
    </div>
    {adding && <Modal title="Add Amazon Bedrock Agents" width="max-w-3xl" onClose={() => setAdding(false)}>
      <AwsSetup onSaved={() => { setAdding(false); void reload(); }} onCancel={() => setAdding(false)} />
    </Modal>}
  </div>;
}

export function AwsSetup({ onSaved, onCancel }: { onSaved: () => void; onCancel: () => void }) {
  const empty = { label: '', access_key_id: '', secret_access_key: '', regions: 'us-east-1' };
  const [draft, setDraft] = useState(empty);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setSaving(true); setError(null);
    try {
      const response = await api<{ connection: AwsConnectionView }>(BASE + '/connections', { method: 'POST', body: draft });
      if (typeof response?.connection?.id !== 'string') throw new Error('The AWS connection was saved without an ID; reload this page to check it');
      setDraft(empty);
      onSaved();
    } catch (failure) { setError(errorOf(failure, 'AWS connection could not be saved')); }
    finally { setSaving(false); }
  };
  const field = (key: keyof typeof draft, label: string, help: string, extra: Record<string, unknown> = {}) => <div>
    <label className="label" htmlFor={`aws-${key}`}>{label}</label>
    <input id={`aws-${key}`} data-testid={`aws-${key}`} className="input" value={draft[key]} onChange={event => setDraft({ ...draft, [key]: event.target.value })} {...extra} />
    <p className="mt-1 text-xs text-ink-3">{help}</p>
  </div>;
  return <form data-testid="aws-setup-form" className="space-y-4" onSubmit={event => void save(event)}>
    <p className="text-sm text-ink-2">Signet signs in to your AWS account with a read-only IAM user and lists its Bedrock agents: AgentCore harnesses, AgentCore runtimes and Agents Classic. Signet checks the sign-in before saving anything and never changes anything in AWS.</p>
    <details className="rounded-lg border border-line p-3 text-sm">
      <summary className="cursor-pointer font-medium">Read-only IAM policy for the user</summary>
      <p className="mt-2 text-xs text-ink-3">IAM → Policies → Create policy → JSON. Paste this, name it SignetBedrockReader, and attach it to a new IAM user (for example signet-reader). Then create an access key for that user (use case: Third-party service).</p>
      <pre className="mono mt-2 overflow-x-auto rounded bg-canvas p-2 text-xs">{AWS_READER_POLICY}</pre>
    </details>
    {field('label', 'Connection name', 'A name you will recognise, e.g. AWS – Test', { maxLength: 120, placeholder: 'AWS Bedrock – Test' })}
    {field('access_key_id', 'Access key ID', 'IAM → Users → signet-reader → Security credentials → Access keys.', { required: true, maxLength: 128, placeholder: 'AKIA…' })}
    {field('secret_access_key', 'Secret access key', 'Shown once, when the access key is created. Stored encrypted.', { type: 'password', autoComplete: 'new-password', required: true, minLength: 16, maxLength: 256 })}
    {field('regions', 'Regions', 'Comma-separated regions where your agents live, e.g. us-east-1 or us-east-1,eu-west-1.', { required: true, maxLength: 200 })}
    <ErrorNote error={error} />
    <div className="flex flex-wrap gap-2">
      <button type="submit" data-testid="aws-save-connection" className="btn-primary" disabled={saving}>{saving ? 'Checking and saving…' : 'Save and connect'}</button>
      <button type="button" className="btn-ghost" onClick={onCancel} disabled={saving}>Cancel</button>
    </div>
  </form>;
}

function SavedAwsConnection({ connection, onChanged }: { connection: AwsConnectionView; onChanged: () => void }) {
  const path = BASE + '/connections/' + encodeURIComponent(connection.id);
  const ok = connection.status === 'connected';
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState<'test' | 'remove' | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const run = async (kind: 'test' | 'remove'): Promise<void> => {
    if (kind === 'remove' && !confirm(`Remove the connection ${connection.label}? Linked agents stay in Signet.`)) return;
    setBusy(kind); setError(null);
    try {
      await api(kind === 'test' ? path + '/test' : path, { method: kind === 'test' ? 'POST' : 'DELETE' });
      if (kind === 'remove') setExpanded(false);
      onChanged();
    } catch (failure) { setError(errorOf(failure, kind === 'test' ? 'Connection test failed' : 'Connection could not be removed')); }
    finally { setBusy(null); }
  };
  return <Card className={`aspect-square [&>div]:h-full !bg-none ${ok ? '!bg-ok-50 !border-ok/30' : '!bg-warn-50 !border-warn/30'}`} pad={false}>
    <section className="h-full" data-testid={`aws-connection-${connection.id}`}>
      <button type="button" data-testid={`aws-open-connection-${connection.id}`} className="flex h-full w-full flex-col items-start rounded-2xl p-4 text-left transition-colors hover:brightness-95 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2" aria-haspopup="dialog" onClick={() => setExpanded(true)}>
        <span className="flex w-full items-start justify-between gap-2">
          <ConnectionIcon tone={ok ? 'ok' : 'warn'}><Cloud size={23} strokeWidth={1.8} /></ConnectionIcon>
          <ArrowUpRight size={16} aria-hidden="true" className="shrink-0 text-ink-3" />
        </span>
        <span className="mt-3 line-clamp-2 break-words text-sm font-semibold">{connection.label}</span>
        <span className={`mt-2 rounded px-1.5 py-0.5 text-[11px] font-medium ${ok ? 'bg-ok-50 text-ok' : 'bg-slate-100 text-ink-2'}`}>{ok ? 'Connected' : 'Check connection'}</span>
        <span className="mt-auto pt-3 text-xs text-ink-3">{connection.linked_agents} linked {connection.linked_agents === 1 ? 'agent' : 'agents'}</span>
        <span className="mt-1 text-xs text-ink-2">View details</span>
      </button>
      {expanded && <Modal title={connection.label} width="max-w-5xl" onClose={() => setExpanded(false)}>
        <p className="text-sm text-ink-2">AWS account {connection.account_id ?? 'unknown (use Test connection)'}</p>
        <p className="mt-1 text-xs text-ink-3">Regions: {connection.regions}</p>
        {connection.status_detail && <p className={`mt-2 text-sm ${ok ? 'text-ok' : 'text-warn'}`}>{connection.status_detail}</p>}
        <ErrorNote error={error} />
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" data-testid={`aws-test-${connection.id}`} className="btn-ghost inline-flex items-center gap-1.5" disabled={busy !== null} onClick={() => void run('test')}><RefreshCw size={14} />{busy === 'test' ? 'Testing…' : 'Test connection'}</button>
          <button type="button" data-testid={`aws-remove-${connection.id}`} className="btn-ghost text-bad" disabled={busy !== null} onClick={() => void run('remove')}>{busy === 'remove' ? 'Removing…' : 'Remove connection'}</button>
        </div>
        <AwsAgents connectionId={connection.id} onChanged={onChanged} />
      </Modal>}
    </section>
  </Card>;
}

function AwsAgents({ connectionId, onChanged }: { connectionId: string; onChanged: () => void }) {
  const path = BASE + '/connections/' + encodeURIComponent(connectionId) + '/agents';
  const { data, error, reload } = useApi<{ items: LinkedAgent[] }>(path);
  const [adding, setAdding] = useState(false);
  const can = useCan();
  return <div className="mt-5 border-t border-line pt-4">
    <h3 className="text-sm font-semibold">Linked Amazon Bedrock agents</h3>
    <p className="mt-1 text-xs text-ink-3">Link an existing agent to the registry, complete review and approval, then follow “Connect the agent to Signet” below.</p>
    {can('agents.write') && <button type="button" data-testid={`aws-link-agent-${connectionId}`} className="btn-primary mt-3" onClick={() => setAdding(true)}>Link existing Amazon Bedrock agent</button>}
    <ErrorNote error={error} />
    {data && !data.items.length && <p className="mt-3 text-sm text-ink-3">No agent linked yet.</p>}
    {data?.items.map(agent => <div key={agent.agent_id} data-testid={`aws-linked-agent-${agent.agent_id}`} className="mt-4 rounded-xl border border-line p-4">
      <Link className="font-semibold text-royal" to={`/agents/${agent.agent_id}`}>{agent.name}</Link>
      <p className="mt-1 break-all text-xs text-ink-3">{agent.kind_label} · {agent.agent_ref}</p>
      <p className="mt-2 text-sm">{agent.gateway_enforcement ? 'Gateway enforcement verified' : 'Gateway enforcement not verified yet'}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Link className="btn-ghost" to={`/agents/${agent.agent_id}?tab=lifecycle`}>Review and approval</Link>
        <Link className="btn-ghost" to={`/agents/${agent.agent_id}?tab=connection`}>Gateway setup</Link>
      </div>
    </div>)}
    <AwsGatewaySteps />
    {adding && <Modal title="Link existing Amazon Bedrock agent" onClose={() => setAdding(false)}>
      <LinkAwsAgentForm path={path} onSaved={() => { setAdding(false); void reload(); onChanged(); }} />
    </Modal>}
  </div>;
}

/** How an approved Bedrock agent is pointed at Signet, in the AWS console. */
function AwsGatewaySteps() {
  return <details className="mt-5 rounded-xl border border-line p-4" data-testid="aws-gateway-steps">
    <summary className="cursor-pointer text-sm font-semibold">Connect the agent to Signet</summary>
    <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-ink-2">
      <li>Finish Review and approval so the agent has a seal. Then open the agent → Gateway setup, choose OAuth and create a client. The MCP URL, Token URL and client ID and secret below come from that page. Signet must be reachable from AWS over HTTPS (for a laptop, through ngrok).</li>
      <li><b>AgentCore harness or runtime.</b> AgentCore console → Outbound Auth → add an OAuth client (client credentials): the Signet client ID and secret, the Token URL, and scope <code>mcp</code> (lowercase).</li>
      <li>AgentCore console → Gateways → Create gateway → add a target of type MCP server. Endpoint: the Signet MCP URL. Outbound authentication: the OAuth client from the step before.</li>
      <li>Open the harness → Update → Tools → turn on Gateway and choose that gateway. Turn off other tools that reach the same systems, so Signet cannot be skipped. Save, then ask the agent a question in the Playground that needs the tool.</li>
      <li><b>Agents Classic.</b> It cannot call an MCP server: its action-group Lambda must get a token from the Token URL (grant_type=client_credentials) and send each tool call to the MCP URL instead of the business system.</li>
      <li>The model runs inside AWS: Signet governs and can block the agent's tool calls, not the model itself.</li>
    </ol>
  </details>;
}

function LinkAwsAgentForm({ path, onSaved }: { path: string; onSaved: () => void }) {
  const [draft, setDraft] = useState({ agent_ref: '', name: '', purpose: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [available, setAvailable] = useState<AwsAgent[] | null>(null);
  const [loading, setLoading] = useState(false);
  const loadAgents = async (): Promise<void> => {
    setLoading(true); setError(null);
    try {
      const result = await api<{ items: AwsAgent[] }>(path + '/available');
      if (!Array.isArray(result?.items)) throw new TypeError('The Amazon Bedrock agent list response must contain items');
      setAvailable(result.items);
    } catch (failure) { setError(errorOf(failure, 'Amazon Bedrock agents could not be loaded')); }
    finally { setLoading(false); }
  };
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setBusy(true); setError(null);
    try { await api(path, { method: 'POST', body: draft }); onSaved(); }
    catch (failure) { setError(errorOf(failure, 'Amazon Bedrock agent could not be linked')); }
    finally { setBusy(false); }
  };
  return <form data-testid="aws-link-agent-form" className="space-y-4" onSubmit={event => void save(event)}>
    <p className="text-sm text-ink-2">Choose an existing Amazon Bedrock agent. Linking registers its identity in Signet; it does not create or change the agent in AWS.</p>
    <button type="button" data-testid="aws-load-agents" className="btn-ghost" disabled={loading || busy} onClick={() => void loadAgents()}>{loading ? 'Loading agents…' : 'Load agents from AWS'}</button>
    {available && <div><label className="label" htmlFor="aws-select-agent">Select an agent</label>
      <select id="aws-select-agent" data-testid="aws-select-agent" className="input" value={available.some(agent => agent.ref === draft.agent_ref) ? draft.agent_ref : ''} onChange={event => {
        const selected = available.find(agent => agent.ref === event.target.value);
        if (selected) setDraft({ ...draft, agent_ref: selected.ref, name: selected.name });
      }}><option value="">Select an agent</option>{available.map(agent => <option key={agent.ref} value={agent.ref}>{agent.name} · {agent.kind_label} · {agent.region} · {agent.status}{agent.active ? '' : ' (not ready)'}</option>)}</select>
      {!available.length && <p className="mt-1 text-xs text-ink-3">No agents were found in these regions. Check the region, that the agent was created, and the IAM policy, then load again.</p>}
    </div>}
    <div><label className="label" htmlFor="aws-agent-ref">Agent reference</label>
      <input id="aws-agent-ref" data-testid="aws-agent-ref" className="input" required maxLength={200} value={draft.agent_ref} onChange={event => setDraft({ ...draft, agent_ref: event.target.value })} />
      <p className="mt-1 text-xs text-ink-3">Filled in when you select an agent above. By hand: agentcore-harness:us-east-1:&lt;harness ID&gt;, agentcore-runtime:us-east-1:&lt;runtime ID&gt;, or us-east-1:&lt;agent ID&gt; for Agents Classic.</p></div>
    <div><label className="label" htmlFor="aws-agent-name">Agent name</label>
      <input id="aws-agent-name" data-testid="aws-agent-name" className="input" required maxLength={200} value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} /></div>
    <div><label className="label" htmlFor="aws-agent-purpose">What does this agent do?</label>
      <textarea id="aws-agent-purpose" data-testid="aws-agent-purpose" className="input" required minLength={10} maxLength={4000} value={draft.purpose} onChange={event => setDraft({ ...draft, purpose: event.target.value })} /></div>
    <ErrorNote error={error} />
    <button type="submit" data-testid="aws-save-agent-link" className="btn-primary" disabled={busy}>{busy ? 'Linking…' : 'Link agent to Signet'}</button>
  </form>;
}
