import { useCallback, useEffect, useState } from 'react';
import { parseAgentAnalytics, type AgentAnalytics as AgentSnapshot, type AgentAnalyticsResponse } from '../../../../packages/core/src/analytics';
import { api } from './api';

export type { ActivityBucket } from '../../../../packages/core/src/analytics';
export interface AgentAnalytics extends AgentSnapshot { color: string }
interface DashboardAnalytics extends Omit<AgentAnalyticsResponse, 'agents'> { agents: AgentAnalytics[] }

export const AGENT_COLORS: string[] = ['#17877d', '#8170d4', '#ce8c3b', '#4b8ecb', '#bd688d', '#718496'];

export function agentColor(index: number): string {
  return AGENT_COLORS[index % AGENT_COLORS.length];
}

export function agentState(agent: AgentAnalytics): { label: string; tone: string; description: string } {
  if (agent.status === 'killed' || agent.enforcement === 'killed') return { label: 'Stopped', tone: 'bad', description: 'This agent has been permanently stopped.' };
  if (agent.enforcement === 'quarantined') return { label: 'Paused', tone: 'warn', description: 'Requests are paused until this agent is reviewed.' };
  if (agent.servicenow && !agent.servicenow.linked) return { label: 'Disconnected', tone: 'neutral', description: 'The ServiceNow connection was removed. Link the existing agent again to restore source monitoring and gateway setup.' };
  if (agent.servicenow?.linked && !agent.servicenow.gateway_enforcement) return agent.servicenow.monitoring
    ? { label: 'Monitored', tone: 'neutral', description: 'ServiceNow activity has been synchronized. Internal calls are not intercepted; gateway enforcement has not been verified.' }
    : { label: 'Linked', tone: 'neutral', description: 'ServiceNow identity is registered. Configure and verify activity monitoring, then complete approval and gateway setup.' };
  if (!agent.valid_to) return { label: 'Awaiting approval', tone: 'neutral', description: 'An approval certificate is needed before this agent can run.' };
  if (Date.parse(agent.valid_to) <= Date.now()) return { label: 'Approval expired', tone: 'warn', description: 'Renew this agent’s approval before it runs again.' };
  if (agent.enforcement === 'throttled') return { label: 'Limited', tone: 'warn', description: 'This agent is running with a reduced request limit.' };
  if (agent.enforcement === 'step_up') return { label: 'Extra checks', tone: 'warn', description: 'Additional safety checks apply to this agent.' };
  if (agent.servicenow?.gateway_enforcement) return { label: 'MCP governed', tone: 'ok', description: 'Routed MCP tool calls are verified. Native chat needs a separately configured and tested ServiceNow Guardian provider.' };
  return { label: 'Governed', tone: 'ok', description: agent.provider.connection_ids.length ? 'Governance approval is active. REST monitoring reports provider activity; internal calls are not intercepted by Signet.' : 'An active approval and Signet safety checks cover this agent.' };
}

export function money(value: number): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: value > 0 && value < 0.01 ? 8 : 2 }).format(value);
}

/** Always show recorded token-based spend; incomplete pricing is explained separately. */
export function gatewayCostDisplay(agents: AgentAnalytics[]): { label: string; detail: string; complete: boolean } {
  const cost = agents.reduce((sum, agent) => sum + agent.cost_usd, 0);
  const unpriced = agents.reduce((sum, agent) => sum + agent.cost_coverage.unpriced_calls, 0);
  const missing = agents.reduce((sum, agent) => sum + agent.cost_coverage.missing_usage_calls + agent.cost_coverage.legacy_records, 0);
  if (unpriced || missing) return {
    complete: false,
    label: money(cost),
    detail: `${unpriced} safety model calls have no recorded rate; ${missing} calls or legacy records lack complete usage. Configure input/output rates in Settings > Gateway cost. Historical records retain their original prices.`,
  };
  return { label: money(cost), detail: 'Recorded gateway and safety-model cost for this reporting period.', complete: true };
}

export function useAgentAnalytics() {
  return useAnalytics('/stats/agents');
}

export function useAllTimeAgentAnalytics() {
  return useAnalytics('/stats/agents/all-time');
}

function useAnalytics(path: string) {
  const [data, setData] = useState<DashboardAnalytics | null>(null);
  const [error, setError] = useState<{ message: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      const result = parseAgentAnalytics(await api<AgentAnalyticsResponse>(path));
      setData({ ...result, agents: result.agents.map((agent, index) => ({ ...agent, color: agentColor(index) })) });
      setError(null);
    } catch (failure) {
      setError({ message: failure instanceof Error ? failure.message : String(failure) });
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    void reload();
    const timer = window.setInterval(() => void reload(), 30_000);
    return () => window.clearInterval(timer);
  }, [reload]);
  return { data, error, loading, reload };
}
