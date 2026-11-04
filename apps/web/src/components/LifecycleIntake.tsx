import { useState } from 'react';
import { DATA_TAGS, type DataTag } from '@signet/core/types';
import { ApiError, api } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, ErrorNote, KV } from './ui';

interface Intake {
  template?: string | null;
  users_affected: ('internal' | 'customers' | 'public')[];
  decisions_about_individuals: boolean;
  individual_domains?: string[];
  data_touched: DataTag[];
  planned_tools?: string[];
  reversibility?: 'yes' | 'partly' | 'no';
  business_value?: string;
}

/** Edit proposal intake through the existing owner-scoped API without preselecting risk answers. */
export function LifecycleIntake({ lifecycleId, intake, onChange }: { lifecycleId: string; intake: Intake; onChange: () => void }) {
  const can = useCan();
  const permitted = can('agents.write') || can('certificates.approve');
  const [editing, setEditing] = useState(permitted && intake.users_affected.length === 0);
  const [draft, setDraft] = useState(intake);
  const [tools, setTools] = useState((intake.planned_tools ?? []).join(', '));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const edit = (): void => { setDraft(intake); setTools((intake.planned_tools ?? []).join(', ')); setError(null); setEditing(true); };
  const save = async (): Promise<void> => {
    setError(null);
    if (!draft.users_affected.length) { setError(new ApiError(400, 'VALIDATION', 'Select at least one group under Who does it affect?')); return; }
    if (draft.decisions_about_individuals && !draft.individual_domains?.length) { setError(new ApiError(400, 'VALIDATION', 'Select a decision domain when this agent makes decisions about individuals')); return; }
    setBusy(true);
    try {
      await api(`/lifecycles/${lifecycleId}/intake`, { method: 'PATCH', body: { users_affected: draft.users_affected, decisions_about_individuals: draft.decisions_about_individuals, individual_domains: draft.individual_domains ?? [], data_touched: draft.data_touched, planned_tools: tools.split(',').map((item) => item.trim()).filter(Boolean), reversibility: draft.reversibility ?? 'partly', business_value: draft.business_value ?? '' } });
      setEditing(false); onChange();
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  return <Card title="Intake" action={permitted && !editing && <button data-testid="lifecycle-intake-edit" className="btn-ghost" onClick={edit}>Edit intake</button>}>
    {editing ? <form data-testid="lifecycle-intake-form" className="space-y-4" onSubmit={(event) => { event.preventDefault(); void save(); }}>
      <fieldset disabled={busy}><legend className="label">Who does it affect? (required)</legend><div className="flex flex-wrap gap-4">{([['internal', 'Employees'], ['customers', 'Customers'], ['public', 'The public']] as const).map(([value, label]) => <label key={value} className="flex items-center gap-2 text-sm"><input data-testid={`lifecycle-audience-${value}`} type="checkbox" checked={draft.users_affected.includes(value)} onChange={(event) => setDraft({ ...draft, users_affected: event.target.checked ? [...draft.users_affected, value] : draft.users_affected.filter((item) => item !== value) })} />{label}</label>)}</div></fieldset>
      <fieldset disabled={busy}><legend className="label">What data does it touch?</legend><div className="flex flex-wrap gap-4">{DATA_TAGS.map((tag) => <label className="flex items-center gap-2 text-sm" key={tag}><input data-testid={`lifecycle-data-${tag}`} type="checkbox" checked={draft.data_touched.includes(tag)} onChange={(event) => setDraft({ ...draft, data_touched: event.target.checked ? [...draft.data_touched, tag] : draft.data_touched.filter((item) => item !== tag) })} />{tag.replaceAll('_', ' ')}</label>)}</div></fieldset>
      <label className="flex items-center gap-2 text-sm"><input data-testid="lifecycle-decisions" type="checkbox" disabled={busy} checked={draft.decisions_about_individuals} onChange={(event) => setDraft({ ...draft, decisions_about_individuals: event.target.checked, individual_domains: event.target.checked ? draft.individual_domains ?? [] : [] })} />It makes or shapes decisions about individual people</label>
      {draft.decisions_about_individuals && <fieldset disabled={busy}><legend className="label">Decision domains</legend><div className="flex flex-wrap gap-4">{['credit', 'employment', 'insurance', 'healthcare', 'education', 'essential_services', 'other'].map((domain) => <label key={domain} className="flex items-center gap-2 text-sm"><input data-testid={`lifecycle-domain-${domain}`} type="checkbox" checked={(draft.individual_domains ?? []).includes(domain)} onChange={(event) => setDraft({ ...draft, individual_domains: event.target.checked ? [...draft.individual_domains ?? [], domain] : (draft.individual_domains ?? []).filter((item) => item !== domain) })} />{domain.replaceAll('_', ' ')}</label>)}</div></fieldset>}
      <label className="label" htmlFor="lifecycle-reversibility">Can its actions be undone?</label><select id="lifecycle-reversibility" data-testid="lifecycle-reversibility" className="input" disabled={busy} value={draft.reversibility ?? 'partly'} onChange={(event) => setDraft({ ...draft, reversibility: event.target.value as 'yes' | 'partly' | 'no' })}><option value="yes">Yes</option><option value="partly">Partly</option><option value="no">No</option></select>
      <label className="label" htmlFor="lifecycle-tools">Planned tools and actions (comma-separated)</label><input id="lifecycle-tools" data-testid="lifecycle-tools" className="input" disabled={busy} value={tools} onChange={(event) => setTools(event.target.value)} />
      <label className="label" htmlFor="lifecycle-business-value">Business value</label><textarea id="lifecycle-business-value" data-testid="lifecycle-business-value" className="input" disabled={busy} value={draft.business_value ?? ''} onChange={(event) => setDraft({ ...draft, business_value: event.target.value })} />
      <ErrorNote error={error} /><div className="flex gap-2"><button data-testid="lifecycle-intake-save" className="btn-primary" disabled={busy}>{busy ? 'Saving…' : 'Save intake'}</button><button type="button" data-testid="lifecycle-intake-cancel" className="btn-ghost" disabled={busy} onClick={() => { setEditing(false); setError(null); }}>Cancel</button></div>
    </form> : <KV rows={[
      ['Template', intake.template ?? '—'], ['Who it affects', intake.users_affected.join(', ') || '—'],
      ['Decisions about individuals', intake.decisions_about_individuals ? `yes (${(intake.individual_domains ?? []).join(', ') || 'domain not given'})` : 'no'],
      ['Data it touches', intake.data_touched.join(', ') || 'none'], ['Planned tools', (intake.planned_tools ?? []).join(', ') || '—'],
      ['Reversibility', intake.reversibility ?? 'partly'], ['Business value', intake.business_value || '—'],
    ]} />}
  </Card>;
}
