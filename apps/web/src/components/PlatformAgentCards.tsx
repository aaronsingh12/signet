import { ArrowUpRight, Bot } from 'lucide-react';
import { Link } from 'react-router-dom';
import { agentState, useAgentAnalytics, type AgentAnalytics } from '../lib/analytics';
import { Card, ErrorNote } from './ui';
import { ConnectionIcon } from './ConnectionIcon';

export function UnlinkedServiceNowAgentCards() {
  const { data, error, loading } = useAgentAnalytics();
  const agents = data?.agents.filter(agent => agent.servicenow !== null && !agent.servicenow.linked);
  return <>
    <ErrorNote error={error} />
    {loading && !data && <p role="status">Loading ServiceNow agents...</p>}
    {agents && agents.length > 0 && <AgentCards agents={agents} />}
  </>;
}

export function ExternalAgentCards() {
  const { data, error, loading } = useAgentAnalytics();
  return <div className="mt-4">
    <h3 className="mb-3 text-sm font-semibold">AI agents</h3>
    <ErrorNote error={error} />
    {loading && !data && <p role="status">Loading platform agents...</p>}
    {data && <div className="grid grid-cols-[repeat(auto-fill,minmax(180px,220px))] gap-4"><AgentCards agents={data.agents.filter(agent => agent.servicenow === null)} /></div>}
  </div>;
}

function AgentCards({ agents }: { agents: AgentAnalytics[] }) {
  return <>
    {!agents.length && <p className="text-sm text-ink-3">No agents registered yet.</p>}
    {agents.map(agent => {
      const state = agentState(agent);
      const tone = state.tone === 'ok' ? 'ok' : state.tone === 'bad' ? 'bad' : 'warn';
      return <Card key={agent.id} className={`aspect-square [&>div]:h-full !bg-none ${tone === 'ok' ? '!bg-ok-50 !border-ok/30' : tone === 'bad' ? '!bg-bad-50 !border-bad/30' : '!bg-warn-50 !border-warn/30'}`} pad={false}>
        <Link data-testid={`identity-details-${agent.id}`} to={`/agents/${agent.id}?tab=connection`} className="flex h-full w-full flex-col items-start rounded-2xl p-4 text-left transition-colors hover:brightness-95 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2">
          <span className="flex w-full items-start justify-between gap-2">
            <ConnectionIcon tone={tone}><Bot size={23} strokeWidth={1.8} /></ConnectionIcon>
            <ArrowUpRight size={16} aria-hidden="true" className="shrink-0 text-ink-3" />
          </span>
          <span className="mt-3 line-clamp-2 break-words text-sm font-semibold">{agent.name}</span>
          <span title={state.description} className="mt-2 text-[11px] font-medium">{state.label}</span>
          <span className="mt-auto pt-3 text-xs text-ink-2">View connection</span>
        </Link>
      </Card>;
    })}
  </>;
}
