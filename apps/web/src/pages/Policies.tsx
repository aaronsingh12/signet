import { Fragment, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, ErrorNote, KV, Mono, PageHeader, Pill } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan, useMe } from '../lib/auth';
import { ago } from '../lib/format';
import { DetectorRelease, ReplayRuns } from '../components/DetectorRelease';



export function Policies() {
  const can = useCan();
  const shortcuts = !!useMe().dev_overrides;
  const { data: det, reload } = useApi<any>('/detectors');
  const { data: cat } = useApi<any>('/catalogue');
  const [error, setError] = useState<ApiError | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const setMode = async (id: string, mode: string) => {
    const reason = prompt(`Reason for moving ${id} to ${mode} (written to the ledger)`);
    if (!reason) return;
    try {
      await api(`/detectors/${id}/mode`, { method: 'POST', body: { mode, reason, dev_override: shortcuts && mode === 'active' && confirm('The 14-day shadow period is not complete. Use the dev override (recorded in the ledger)?') } });
      setError(null);
      void reload();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <>
      <PageHeader title="Safety rules" subtitle="Review the rules and detection services that check your agents’ requests. Changes here affect your workspace." />
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
            <thead><tr>{['Detector', 'Version', 'Pinned hash', 'Mode', 'Shadow since', 'Last change', 'Notes', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {(det?.items ?? []).map((d: any) => (
                <Fragment key={d.id}>
                <tr>
                  <td className="td mono font-medium">{d.id}</td>
                  <td className="td mono text-xs">{d.version}</td>
                  <td className="td mono text-xs" title={d.model_sha256 ?? ''}>{d.model_sha256 ? d.model_sha256.slice(0, 12) : '—'}</td>
                  <td className="td"><Pill value={d.mode === 'active' ? 'allow' : d.mode === 'shadow' ? 'allow_with_obligations' : 'none'} label={d.mode} /></td>
                  <td className="td text-xs">{ago(d.shadow_since)}</td>
                  <td className="td text-xs">{d.promoted_by ? `${d.promoted_by} · ${ago(d.promoted_at)}` : '—'}</td>
                  <td className="td max-w-md text-xs text-ink-2">{d.notes}</td>
                  <td className="td whitespace-nowrap">
                    {d.version !== 'not-deployed' && <button className="mr-2 text-xs text-royal hover:underline" onClick={() => setOpen(open === d.id ? null : d.id)}>{open === d.id ? 'Hide release' : 'Release'}</button>}
                    {can('detectors.manage') && d.version !== 'not-deployed' && (
                      <>
                        {d.mode !== 'shadow' && <button className="mr-2 text-xs text-royal hover:underline" onClick={() => void setMode(d.id, 'shadow')}>Shadow</button>}
                        {d.mode === 'shadow' && <button className="mr-2 text-xs text-royal hover:underline" onClick={() => void setMode(d.id, 'active')}>Promote</button>}
                        {d.mode !== 'off' && <button className="text-xs text-ink-3 hover:underline" onClick={() => void setMode(d.id, 'off')}>Off</button>}
                      </>
                    )}
                  </td>
                </tr>
                {open === d.id && <tr><td colSpan={8} className="p-0"><DetectorRelease id={d.id} onChange={() => void reload()} /></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
          <div className="border-t border-line px-4 py-2 text-xs text-ink-3">A detector that is off, in shadow or pending leaves Tier 0 in charge, and T1/T2 allows become hold for approval (RB-INV-06). Promotion is human-only and needs 14 days in shadow (RB-MOD-03), a passing benchmark, a result at least as good as the version it replaces, and Security plus AI Assurance sign-off (DA 6). Each version is pinned by hash; a gateway running anything else treats the detector as unavailable.</div>
        </Card>
        <ReplayRuns />
        <Card title="Guardrails in force" className="xl:col-span-2">
          <p className="text-sm text-ink-2">Every rule, data check, detector and automatic stop, with the limits in force now, is listed in one place on the <Link className="text-royal hover:underline" to="/guardrails">Guardrails</Link> page.</p>
        </Card>
      </div>
    </>
  );
}
