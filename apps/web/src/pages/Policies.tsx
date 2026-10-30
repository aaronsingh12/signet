import { useState } from 'react';
import { Card, ErrorNote, KV, Mono, PageHeader, Pill } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';

const BASELINE = [
  ['RB-INV-19', 'Agents may call only the cloud LLM; any other provider is out-of-manifest'],
  ['RB-INV-16', 'Credentials and secrets never reach a model'],
  ['RB-BL-03', 'Per-request input cap: 32,000 tokens'],
  ['RB-BL-04', 'Per-request cost cap: USD 5 (hold for approval)'],
  ['RB-BL-10', 'Responses are scanned for secrets and redacted'],
  ['RB-BL-12', 'Session taint: privileged actions after injected content need a person'],
  ['RB-PRIV-03', 'Critical actions need HITL on T1-T3'],
  ['RB-PRIV-04', 'Privileged actions need HITL on T1/T2 unless waived'],
  ['RB-PRIV-07', 'L0/L1 agents need HITL for every write'],
  ['RB-KILL-01', 'Hijack: injection in a tool response, then a privileged action'],
  ['RB-KILL-02', 'Exfiltration: Restricted data to a destination the seal does not allow'],
  ['RB-KILL-04', 'Repeat violation: 3 out-of-manifest attempts in 10 minutes'],
];

export function Policies() {
  const can = useCan();
  const { data: det, reload } = useApi<any>('/detectors');
  const { data: cat } = useApi<any>('/catalogue');
  const [error, setError] = useState<ApiError | null>(null);
  const setMode = async (id: string, mode: string) => {
    const reason = prompt(`Reason for moving ${id} to ${mode} (written to the ledger)`);
    if (!reason) return;
    try {
      await api(`/detectors/${id}/mode`, { method: 'POST', body: { mode, reason, dev_override: mode === 'active' && confirm('The 14-day shadow period is not complete. Use the dev override (recorded in the ledger)?') } });
      setError(null);
      void reload();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <>
      <PageHeader title="Policies & detectors" subtitle="Tier 0 rules decide; detectors can only add caution (DA 2). Tenant rules can be tightened, never loosened without approval." />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="The cloud LLM (Rulebook D-17)">
          {cat?.catalogue?.map((c: any) => (
            <KV key={c.model} rows={[['Model', <Mono key="m">{c.model}</Mono>], ['Provider reports', <Mono key="u">{c.upstream_model}</Mono>], ['Family', c.family], ['Region', `${c.region} (provider terms record pending, RB-PROV-03)`], ['Code-approved', c.code_approved ? 'yes' : 'no']]} />
          ))}
        </Card>
        <Card title="Policy engine">
          <KV
            rows={[
              ['Source', <Mono key="s">policy/signet.rego</Mono>],
              ['Conformance', '20 shared cases run against the Rego policy (OPA) and the gateway evaluator'],
              ['Evaluation', 'In-process; OPA WebAssembly when policy.wasm is built by CI, otherwise the conformance-tested TypeScript evaluator'],
              ['Precedence', 'Deny overrides approval; approval overrides obligations (RB-PREC-03/04)'],
            ]}
          />
        </Card>
        <Card title="Detectors (Tier 1)" className="xl:col-span-2" pad={false}>
          <ErrorNote error={error} />
          <table className="w-full">
            <thead><tr>{['Detector', 'Version', 'Mode', 'Shadow since', 'Last change', 'Notes', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {(det?.items ?? []).map((d: any) => (
                <tr key={d.id}>
                  <td className="td mono font-medium">{d.id}</td>
                  <td className="td mono text-xs">{d.version}</td>
                  <td className="td"><Pill value={d.mode === 'active' ? 'allow' : d.mode === 'shadow' ? 'allow_with_obligations' : 'none'} label={d.mode} /></td>
                  <td className="td text-xs">{ago(d.shadow_since)}</td>
                  <td className="td text-xs">{d.promoted_by ? `${d.promoted_by} · ${ago(d.promoted_at)}` : '—'}</td>
                  <td className="td max-w-md text-xs text-ink-2">{d.notes}</td>
                  <td className="td whitespace-nowrap">
                    {can('detectors.manage') && d.version !== 'not-deployed' && (
                      <>
                        {d.mode !== 'shadow' && <button className="mr-2 text-xs text-royal hover:underline" onClick={() => void setMode(d.id, 'shadow')}>Shadow</button>}
                        {d.mode === 'shadow' && <button className="mr-2 text-xs text-royal hover:underline" onClick={() => void setMode(d.id, 'active')}>Promote</button>}
                        {d.mode !== 'off' && <button className="text-xs text-ink-3 hover:underline" onClick={() => void setMode(d.id, 'off')}>Off</button>}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="border-t border-line px-4 py-2 text-xs text-ink-3">A detector that is off, in shadow or pending leaves Tier 0 in charge, and T1/T2 allows become hold for approval (RB-INV-06). Promotion is human-only and needs 14 days in shadow (RB-MOD-03).</div>
        </Card>
        <Card title="Tenant baseline and kill rules in force" className="xl:col-span-2" pad={false}>
          <table className="w-full">
            <tbody>
              {BASELINE.map(([id, text]) => (
                <tr key={id}>
                  <td className="td w-32 mono font-medium">{id}</td>
                  <td className="td text-ink-2">{text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </>
  );
}
