import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { parseGatewayCosts, type GatewayCostsReport } from '../../../../packages/core/src/gateway-costs';
import { ModelPriceEditor } from '../components/ModelPricing';
import { Card, Empty, ErrorNote, PageHeader } from '../components/ui';
import { api } from '../lib/api';
import { useCan } from '../lib/auth';
import { money } from '../lib/analytics';
import { num } from '../lib/format';

async function fetchCosts(days: number): Promise<GatewayCostsReport> {
  return parseGatewayCosts(await api<GatewayCostsReport>(`/stats/gateway-costs?days=${days}`));
}

export function GatewayCosts() {
  const can = useCan();
  const [days, setDays] = useState(30);
  const [agentId, setAgentId] = useState('');
  const [data, setData] = useState<GatewayCostsReport | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(false);
  const latestRequest = useRef(0);
  const load = useCallback(async (): Promise<void> => {
    const request = ++latestRequest.current;
    setLoading(true);
    try {
      const report = await fetchCosts(days);
      if (request === latestRequest.current) { setData(report); setError(null); }
    } catch (failure) { if (request === latestRequest.current) setError(failure instanceof Error ? failure : new Error(String(failure))); }
    finally { if (request === latestRequest.current) setLoading(false); }
  }, [days]);
  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30_000);
    return () => { window.clearInterval(timer); latestRequest.current++; };
  }, [load]);
  const current = data?.days === days ? data : null;
  const agents = current?.agents.filter(agent => !agentId || agent.id === agentId) ?? [];
  const total = (key: 'tokens_in' | 'tokens_out' | 'cost_usd' | 'safety_cost_usd' | 'estimated_safety_calls' | 'estimated_safety_cost_usd' | 'unpriced_safety_calls' | 'missing_safety_usage_calls' | 'legacy_safety_records'): number => agents.reduce((sum, agent) => sum + agent[key], 0);
  return <>
    <PageHeader title="Gateway cost" subtitle="Manage model token prices and see recorded gateway usage for every AI agent." actions={<button className="btn-ghost" data-testid="gateway-cost-refresh" disabled={loading} onClick={() => void load()}>{loading ? 'Refreshing…' : 'Refresh'}</button>} />
    <ErrorNote error={error} />
    <div className="mb-5 flex flex-wrap gap-4">
      <div><label className="label" htmlFor="gateway-cost-period">Period</label><select id="gateway-cost-period" data-testid="gateway-cost-period" className="input" value={days} onChange={event => setDays(Number(event.target.value))}>{[1, 7, 30, 90].map(value => <option key={value} value={value}>Last {value === 1 ? '24 hours' : `${value} days`}</option>)}</select></div>
      <div><label className="label" htmlFor="gateway-cost-agent">AI agent</label><select id="gateway-cost-agent" data-testid="gateway-cost-agent" className="input" value={agentId} onChange={event => setAgentId(event.target.value)}><option value="">All agents</option>{(current?.agents ?? []).map(agent => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select></div>
    </div>
    {!current && !error && <p className="mb-4 text-sm text-ink-3" role="status">Loading gateway costs…</p>}
    {current && <>
      <div className="mb-5 grid gap-4 sm:grid-cols-3">
        <Card title="Recorded gateway cost"><strong className="text-2xl" data-testid="gateway-cost-total">{money(total('cost_usd'))}</strong><p className="mt-2 text-xs text-ink-3">Includes agent model and Signet safety-review usage</p></Card>
        <Card title="Input tokens"><strong className="text-2xl" data-testid="gateway-cost-input-tokens">{num(total('tokens_in'))}</strong></Card>
        <Card title="Output tokens"><strong className="text-2xl" data-testid="gateway-cost-output-tokens">{num(total('tokens_out'))}</strong></Card>
      </div>
      {(total('unpriced_safety_calls') > 0 || total('missing_safety_usage_calls') > 0 || total('legacy_safety_records') > 0) && <p className="mb-4 rounded-lg border border-line p-3 text-sm text-warn" data-testid="gateway-cost-coverage">{num(total('unpriced_safety_calls'))} safety calls have zero or missing prices; {num(total('missing_safety_usage_calls'))} calls lack provider token counts; {num(total('legacy_safety_records'))} older Guardian records lack split usage. Totals include only recorded usage at available rates. Set actual prices below for new calls.</p>}
      {total('estimated_safety_calls') > 0 && <p className="mb-4 rounded-lg border border-line p-3 text-sm text-ink-2" data-testid="gateway-cost-estimated">Includes {money(total('estimated_safety_cost_usd'))} estimated at current rates for {num(total('estimated_safety_calls'))} safety calls that ran before a rate was set. Calls that ran at a rate keep that rate.</p>}
      <p className="mb-4 text-sm text-ink-3" data-testid="gateway-safety-cost">Signet safety-review cost: {money(total('safety_cost_usd'))}. Safety overhead is separate from the approved agent model budget.</p>
      <Card title="Usage and cost by agent" pad={false}>
        <p className="px-4 py-3 text-xs text-ink-3">{new Date(current.from).toLocaleString()} – {new Date(current.to).toLocaleString()}. Updates every 30 seconds. Agents with no recorded usage are included.</p>
        {agents.length ? <div className="overflow-x-auto"><table className="w-full"><thead><tr>{['AI agent', 'Model calls', 'Safety calls', 'Tool calls', 'Input tokens', 'Output tokens', 'Gateway cost (USD)', 'Approved daily budget'].map(label => <th key={label} className="th">{label}</th>)}</tr></thead><tbody>{agents.map(agent => <tr key={agent.id} data-testid={`gateway-cost-agent-${agent.id}`}>
          <td className="td"><Link className="font-medium text-royal" to={`/agents/${agent.id}`}>{agent.name}</Link><div className="text-xs text-ink-3">{agent.handle} · {agent.status}</div></td>
          <td className="td">{num(agent.model_calls)}</td><td className="td">{num(agent.safety_calls)}</td><td className="td">{num(agent.tool_calls)}</td><td className="td">{num(agent.tokens_in)}</td><td className="td">{num(agent.tokens_out)}</td><td className="td">{money(agent.cost_usd)}</td>
          <td className="td"><div>{agent.daily_budget_usd === null ? 'No active approval' : agent.daily_budget_usd === 0 ? 'No cost cap' : money(agent.daily_budget_usd)}</div><Link className="text-xs text-royal" to={`/agents/${agent.id}?tab=lifecycle`}>Review budget</Link></td>
        </tr>)}</tbody></table></div> : <Empty>No agents match this selection.</Empty>}
      </Card>
      <Card title="Model usage by agent" className="mt-5">
        {agents.filter(agent => agent.models.length > 0).map(agent => <details key={agent.id} className="border-b border-line py-3" data-testid={`gateway-cost-models-${agent.id}`}><summary className="cursor-pointer font-medium">{agent.name}</summary><div className="overflow-x-auto"><table className="mt-3 w-full"><thead><tr>{['Source', 'Model', 'Calls', 'Input tokens', 'Output tokens', 'Recorded USD'].map(label => <th className="th" key={label}>{label}</th>)}</tr></thead><tbody>{agent.models.map(model => <tr key={`${model.source}:${model.model}`}><td className="td">{model.source === 'safety_review' ? 'Signet safety review' : 'Agent model'}</td><td className="td break-all">{model.model}</td><td className="td">{num(model.calls)}</td><td className="td">{num(model.tokens_in)}</td><td className="td">{num(model.tokens_out)}</td><td className="td">{money(model.cost_usd)}{model.estimated_cost_usd ? <div className="text-xs text-ink-3">incl. {money(model.estimated_cost_usd)} estimated at current rate</div> : null}</td></tr>)}</tbody></table></div></details>)}
        {!agents.some(agent => agent.models.length > 0) && <p className="text-sm text-ink-3">No model usage with detailed accounting recorded for this selection. Historical Guardian records may lack input/output splits.</p>}
      </Card>
      <Card title="Model token prices" className="mt-5">
        <p className="text-sm text-ink-2">Public prices are fetched automatically where available. Use them or enter your contracted input and output prices in USD per 1 million tokens, then save. Saved manual rates are preserved. Prices apply to all agents using that model and affect new request costs and cost limits. Costs already recorded at a rate stay unchanged; calls recorded before any rate was set are shown at the current rate as an estimate.</p>
        {!can('tenant.admin') && <p className="mt-2 text-sm text-ink-3">A workspace administrator can update prices.</p>}
        {current.models.map(model => <ModelPriceEditor key={model.model} model={model} canEdit={can('tenant.admin')} onSaved={async () => { setData(await fetchCosts(days)); setError(null); }} />)}
        {!current.models.length && <Empty>No models are registered. Connect a model from an agent’s Gateway setup first.</Empty>}
      </Card>
      <p className="mt-4 text-sm text-ink-3">Cost = (input tokens × input price + output tokens × output price) / 1,000,000. Signet safety-review calls are included separately from agent model calls. ServiceNow subscriptions and its internal AI model usage are excluded. Configured token rates are estimates; provider cache discounts, fees and subscriptions may differ. A $0.00 value can mean no gateway model usage or zero configured prices.</p>
    </>}
  </>;
}
