import { ActivityChart, AgentMetrics, OutcomeChart } from './AgentCharts';
import { ErrorNote } from './ui';
import { agentState, money, useAgentAnalytics } from '../lib/analytics';
import { date, num } from '../lib/format';

export function AgentInsights({ agentId }: { agentId: string }) {
  const { data, error, loading } = useAgentAnalytics();
  const agent = data?.agents.find((item) => item.id === agentId);
  if (error) return <ErrorNote error={error} />;
  if (!data && loading) return <div className="dashboard-loading" role="status">Loading this agent’s activity…</div>;
  if (!agent) return <p className="text-sm text-ink-3">This agent has no current analytics snapshot.</p>;
  const state = agentState(agent);
  return <div className="detail-overview" data-testid="agent-insights">
    <div className={`safety-banner ${state.tone === 'ok' ? '' : 'attention'}`}><div><strong>{agent.name} · {state.label}</strong><p>{state.description}</p></div></div>
    <AgentMetrics agents={[agent]} />
    <div className="chart-layout"><section className="chart-card"><div className="chart-heading"><div><h2>Activity over the last 24 hours</h2><p>Hourly requests for {agent.name}</p></div></div><ActivityChart agents={[agent]} /></section><section className="chart-card"><div className="chart-heading"><div><h2>Request outcomes</h2><p>Completed, blocked, review and service errors</p></div></div><OutcomeChart agents={[agent]} /></section></div>
    <div className="chart-card mt-5"><div className="chart-heading"><div><h2>At a glance</h2><p>The essentials for this agent</p></div></div><dl className="mt-5 grid gap-6 text-sm sm:grid-cols-2 xl:grid-cols-4"><div><dt className="text-xs text-ink-3">Responsible owner</dt><dd className="mt-2 break-words font-medium">{agent.owner}</dd></div><div><dt className="text-xs text-ink-3">Approval valid until</dt><dd className="mt-2 font-medium">{agent.valid_to ? date(agent.valid_to) : 'No active approval'}</dd></div><div><dt className="text-xs text-ink-3">AI usage in the last 24h</dt><dd className="mt-2 font-medium">{num(agent.tokens)} tokens</dd><p className="chart-note">Tokens measure the text processed by the model.</p></div><div><dt className="text-xs text-ink-3">Daily spending limit</dt><dd className="mt-2 font-medium">{agent.daily_budget_usd === null ? 'No active budget' : money(agent.daily_budget_usd)}</dd></div></dl></div>
  </div>;
}
