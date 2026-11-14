import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono, PageHeader, Pill, Stat } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan, useMe } from '../lib/auth';
import { FrameworkSheetImport } from '../components/FrameworkSheetImport';
import { AuditPacks } from '../components/AuditPacks';
import { ago } from '../lib/format';

// Control Library & Compliance (BP 9): Signet Controls are the hub; framework requirements map to
// them. Automated controls are tested continuously from live evidence; scores follow the results.
// Coverage shows how many of a framework's requirements have a Signet Control at all.

const STATUS_PILL: Record<string, string> = { effective: 'allow', partially_effective: 'require_approval', ineffective: 'deny', not_tested: 'none', no_control: 'none' };
const STATUS_LABEL: Record<string, string> = { no_control: 'no control yet' };
const CATEGORY: Record<string, string> = { ai_risk: 'AI risk', ai_security: 'AI security', ai_law: 'AI law', security: 'Security', privacy: 'Privacy', resilience: 'Resilience', threat: 'Threats', regional: 'Regional', other: 'Imported' };

function StatusPill({ status }: { status: string | null }) {
  const s = status ?? 'not_tested';
  return <Pill value={STATUS_PILL[s]} label={STATUS_LABEL[s] ?? s.replace('_', ' ')} />;
}

export function Controls() {
  const can = useCan();
  const lib = useApi<any>('/library');
  const scores = useApi<any>('/compliance/scores');
  const [framework, setFramework] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [importing, setImporting] = useState<{ id: string; name: string } | 'new' | null>(null);
  const reload = () => Promise.all([lib.reload(), scores.reload()]);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
      await reload();
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const evaluate = () => run(() => api('/library/evaluate', { method: 'POST' }));
  const toggle = (f: any) => {
    const reason = window.prompt(`${f.enabled ? 'Switch off' : 'Switch on'} ${f.name}. Reason (recorded in the ledger):`);
    if (reason?.trim()) void run(() => api(`/library/frameworks/${f.framework_id}/enabled`, { method: 'POST', body: { enabled: !f.enabled, reason } }));
  };
  const importOscal = (file: File, subset: string) =>
    run(async () => {
      const document = JSON.parse(await file.text());
      const r = await api<any>('/library/import/oscal', { method: 'POST', body: { document, subset } });
      setNote(`Imported ${r.controls} controls into ${r.framework_id}; ${r.in_scope} count toward the score.${r.built_in_not_in_profile?.length ? ` Not in the official baseline: ${r.built_in_not_in_profile.join(', ')}.` : ''}`);
    });

  const loadNist = () =>
    run(async () => {
      const r = await api<any>('/library/import/official', { method: 'POST', body: { source: 'nist-800-53' } });
      setNote(`Loaded the official NIST SP 800-53 catalog (${r.controls} controls, SHA-256 checked); ${r.in_scope} AI-relevant controls count toward the score.`);
    });

  const items: any[] = scores.data?.items ?? [];
  const enabled = items.filter((f) => f.enabled);
  const off = items.filter((f) => !f.enabled);
  const selected = items.find((f) => f.framework_id === framework);
  const controls = (lib.data?.controls ?? []).filter(
    (c: any) => (!framework || c.mappings.some((m: any) => m.framework_id === framework)) && (!q || `${c.id} ${c.objective} ${c.domain}`.toLowerCase().includes(q.toLowerCase())),
  );
  const count = (s: string) => (lib.data?.controls ?? []).filter((c: any) => (c.status ?? 'not_tested') === s).length;
  const linksOf = (reqId: string) => (lib.data?.controls ?? []).flatMap((c: any) => c.mappings.filter((m: any) => m.requirement_id === reqId).map((m: any) => ({ ...m, control_id: c.id })));

  const card = (f: any) => (
    <button key={f.framework_id} onClick={() => setFramework(framework === f.framework_id ? null : f.framework_id)} className={`card px-3 py-2.5 text-left ${framework === f.framework_id ? 'ring-2 ring-royal' : ''}`}>
      <div className="text-[10px] uppercase tracking-wide text-ink-3">{CATEGORY[f.category] ?? f.category}</div>
      <div className="line-clamp-2 text-xs font-medium text-ink-2">{f.name}</div>
      <div className="mt-1 text-xl font-semibold">{f.score === null ? '—' : `${f.score}%`}</div>
      <div className="mt-1 h-1.5 rounded bg-slate-100"><div className="h-1.5 rounded bg-royal" style={{ width: `${f.score ?? 0}%` }} /></div>
      <div className="mt-1 text-[11px] text-ink-3">{f.requirements.length} requirements · {f.coverage ?? 0}% covered</div>
    </button>
  );

  return (
    <>
      <PageHeader
        title="Control Library & Compliance"
        subtitle="One set of Signet Controls, mapped to each framework. Score: requirements whose mapped controls are all effective. Covered: requirements that have at least one Signet Control."
        actions={<button className="btn-primary" disabled={busy} onClick={() => void evaluate()}>{busy ? 'Working…' : 'Evaluate now'}</button>}
      />
      <ErrorNote error={error} />
      {note && <Card className="mb-4"><p className="text-sm text-ink-2">{note}</p></Card>}
      <div className="mb-4 grid gap-3 md:grid-cols-4">
        <Stat label="Effective" value={count('effective')} tone="ok" hint="controls" />
        <Stat label="Partially effective" value={count('partially_effective')} tone="warn" hint="controls" />
        <Stat label="Ineffective" value={count('ineffective')} tone="bad" hint="controls" />
        <Stat label="Not tested" value={count('not_tested')} hint="manual or no evidence yet" />
      </div>
      <div className="mb-4 grid gap-3 md:grid-cols-3 xl:grid-cols-6">{enabled.map(card)}</div>

      {importing && (
        <FrameworkSheetImport
          target={importing === 'new' ? undefined : importing}
          onCancel={() => setImporting(null)}
          onDone={(message) => { setImporting(null); setNote(message); void reload(); }}
        />
      )}

      {selected && (
        <Card pad={false} className="mb-4" title={`${selected.name}: requirements`} action={can('library.edit') && <button className="btn-ghost" disabled={busy} onClick={() => toggle(selected)}>{selected.enabled ? 'Switch off' : 'Switch on'}</button>}>
          <table className="w-full">
            <thead><tr>{['Requirement', 'Summary', 'Status', 'Signet Controls'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {selected.requirements.map((r: any) => (
                <tr key={r.id}>
                  <td className="td"><Mono>{r.external_id}</Mono></td>
                  <td className="td text-sm">{r.summary}</td>
                  <td className="td"><StatusPill status={r.status} /></td>
                  <td className="td text-xs text-ink-2"><RequirementLinks requirementId={r.id} links={linksOf(r.id)} controls={lib.data?.controls ?? []} canEdit={can('library.edit')} run={run} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      <Card pad={false} className="mb-4" title={framework ? `Controls mapped to ${selected?.name ?? framework}` : 'All controls'} action={<input className="input w-56" placeholder="Search controls" value={q} onChange={(e) => setQ(e.target.value)} />}>
        {controls.length ? (
          <table className="w-full">
            <thead><tr>{['Control', 'Objective', 'Test', 'Status', 'Maps to', 'Evaluated'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {controls.map((c: any) => {
                const maps = c.mappings.filter((m: any) => !framework || m.framework_id === framework);
                return (
                  <tr key={c.id}>
                    <td className="td"><Mono>{c.id}</Mono><div className="text-[11px] text-ink-3">{c.domain} · {c.severity}</div></td>
                    <td className="td text-sm">{c.objective}<div className="text-xs text-ink-3">{c.detail}</div></td>
                    <td className="td text-xs text-ink-2">{c.test_type.replace('_', ' ')}</td>
                    <td className="td"><StatusPill status={c.status} /></td>
                    <td className="td text-xs text-ink-2" title={maps.map((m: any) => `${m.framework_id} ${m.external_id}: ${m.relationship.replace('_', ' ')}`).join('\n')}>
                      {maps.length > 6 ? `${maps.slice(0, 6).map((m: any) => m.external_id).join(', ')} +${maps.length - 6} more` : maps.map((m: any) => m.external_id).join(', ') || '—'}
                    </td>
                    <td className="td text-xs text-ink-2">{ago(c.evaluated_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <Empty>No controls match.</Empty>
        )}
      </Card>

      {can('evidence.export') && <AuditPacks frameworks={items} />}

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Switched off for this organisation">
          {off.length ? (
            <ul className="space-y-2">
              {off.map((f) => (
                <li key={f.framework_id} className="flex items-center justify-between gap-2 text-sm">
                  <button className="text-left text-ink-2 hover:underline" onClick={() => setFramework(f.framework_id)}>{f.name} <span className="text-xs text-ink-3">({CATEGORY[f.category] ?? f.category})</span></button>
                  {can('library.edit') && <button className="btn-ghost" disabled={busy} onClick={() => toggle(f)}>Switch on</button>}
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-ink-3">Every framework is switched on.</p>}
        </Card>
        <Card title="Licence needed">
          <p className="mb-2 text-xs text-ink-3">Signet includes these as empty, locked entries. Once you hold a licence, load your own copy from a spreadsheet; then link its requirements to Signet Controls and switch it on.</p>
          <ul className="space-y-2 text-sm">
            {(lib.data?.licence_held ?? []).map((x: any) => (
              <li key={x.id} className="flex items-center justify-between gap-2">
                <span><span className="font-medium">{x.name}</span> <span className="text-xs text-ink-3">— {x.reason}</span></span>
                {can('library.edit') && <button className="btn-ghost" disabled={busy} onClick={() => setImporting({ id: x.id, name: x.name })}>Load licensed copy</button>}
              </li>
            ))}
            {!(lib.data?.licence_held ?? []).length && <li className="text-ink-3">None: every licensed framework has been loaded.</li>}
          </ul>
        </Card>
        {can('library.edit') && (
          <Card title="Import from a spreadsheet">
            <p className="mb-2 text-xs text-ink-3">Load your own framework or internal policy from a CSV or Excel file: one row per requirement.</p>
            <button className="btn-primary" disabled={busy} onClick={() => setImporting('new')}>Import spreadsheet</button>
          </Card>
        )}
        {can('library.edit') && (
          <Card title="Import an OSCAL catalog or profile">
            <p className="mb-2 text-xs text-ink-3">All 1,196 NIST SP 800-53 controls, or any other OSCAL catalog or profile. By default only AI-relevant controls count toward the score.</p>
            <button className="btn-ghost mb-2 w-full" disabled={busy} onClick={() => void loadNist()}>Load the official NIST SP 800-53 Rev. 5.2.0 catalog</button>
            <p className="mb-2 text-xs text-ink-3">Signet downloads it from NIST (fixed version, SHA-256 checked). Or upload your own file:</p>
            <OscalImport busy={busy} onImport={importOscal} />
          </Card>
        )}
      </div>
    </>
  );
}

function OscalImport({ busy, onImport }: { busy: boolean; onImport: (file: File, subset: string) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [subset, setSubset] = useState('ai');
  return (
    <div className="flex flex-wrap items-center gap-2">
      <input type="file" accept=".json,application/json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
      <select className="input w-48" value={subset} onChange={(e) => setSubset(e.target.value)}>
        <option value="ai">Score AI-relevant controls</option>
        <option value="all">Score every control</option>
      </select>
      <button className="btn-primary" disabled={busy || !file} onClick={() => file && onImport(file, subset)}>Import</button>
    </div>
  );
}

// Links from one requirement to Signet Controls. A link someone adds counts once a second person
// confirms it; built-in links come reviewed with the Signet catalogue.
function RequirementLinks({ requirementId, links, controls, canEdit, run }: { requirementId: string; links: any[]; controls: any[]; canEdit: boolean; run: (fn: () => Promise<unknown>) => Promise<void> }) {
  const me = useMe();
  const [open, setOpen] = useState(false);
  const [hints, setHints] = useState<any[] | null>(null);
  const [pick, setPick] = useState('');
  const [rel, setRel] = useState('subset_of');
  const show = async () => {
    setOpen(true);
    setHints((await api<any>(`/library/suggestions?requirement_id=${encodeURIComponent(requirementId)}`)).items);
  };
  const body = (control_id: string) => ({ requirement_id: requirementId, control_id });
  const propose = (control_id: string) => run(() => api('/library/mappings', { method: 'POST', body: { ...body(control_id), relationship: rel } })).then(() => { setOpen(false); setPick(''); });
  return (
    <div className="space-y-1">
      {links.map((l) => {
        const pending = l.origin === 'customer' && !l.reviewed_by;
        return (
          <div key={l.control_id} className="flex flex-wrap items-center gap-1" title={`${l.relationship.replace('_', ' ')}${l.coverage_note ? `: ${l.coverage_note}` : ''}`}>
            <Mono>{l.control_id}</Mono>
            {pending && <span className="text-[11px] text-amber-700">waiting for a second person</span>}
            {canEdit && pending && l.proposed_by !== me.principal.id && <button className="btn-ghost px-1 py-0 text-[11px]" onClick={() => void run(() => api('/library/mappings/confirm', { method: 'POST', body: body(l.control_id) }))}>Confirm</button>}
            {canEdit && l.origin === 'customer' && (
              <button className="btn-ghost px-1 py-0 text-[11px]" onClick={() => { const reason = window.prompt('Reason for removing this link:'); if (reason?.trim()) void run(() => api('/library/mappings/remove', { method: 'POST', body: { ...body(l.control_id), reason } })); }}>Remove</button>
            )}
          </div>
        );
      })}
      {!links.length && <span>—</span>}
      {canEdit && !open && <button className="btn-ghost px-1 py-0 text-[11px]" onClick={() => void show()}>Link a control</button>}
      {open && (
        <div className="mt-1 space-y-1 rounded border border-slate-200 p-2">
          {hints === null ? <div className="text-[11px] text-ink-3">Finding suggestions…</div> : hints.length ? (
            hints.map((h) => (
              <div key={h.control_id} className="flex items-center justify-between gap-2">
                <span title={h.why}><Mono>{h.control_id}</Mono> <span className="text-[11px]">{h.objective}</span></span>
                <button className="btn-ghost px-1 py-0 text-[11px]" onClick={() => void propose(h.control_id)}>Link</button>
              </div>
            ))
          ) : <div className="text-[11px] text-ink-3">No suggestions; pick a control below.</div>}
          <div className="flex flex-wrap items-center gap-1">
            <select className="input w-44 py-0.5 text-xs" value={pick} onChange={(e) => setPick(e.target.value)}>
              <option value="">Any control…</option>
              {controls.filter((c) => !links.some((l) => l.control_id === c.id)).map((c) => <option key={c.id} value={c.id}>{c.id}: {c.objective.slice(0, 50)}</option>)}
            </select>
            <select className="input w-32 py-0.5 text-xs" value={rel} onChange={(e) => setRel(e.target.value)} title="How much of the requirement the control covers">
              <option value="subset_of">covers part</option>
              <option value="equivalent">covers all</option>
              <option value="superset_of">covers all and more</option>
              <option value="intersects">overlaps</option>
            </select>
            <button className="btn-ghost px-1 py-0 text-[11px]" disabled={!pick} onClick={() => void propose(pick)}>Link</button>
            <button className="btn-ghost px-1 py-0 text-[11px]" onClick={() => setOpen(false)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
