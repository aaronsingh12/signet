import { useState } from 'react';
import { Pencil } from 'lucide-react';
import type { Coverage, CustomRule, RuleEdit, RuleStatus } from '@signet/core/rulebook';
import { ErrorNote, Pill } from './ui';

export const RULE_COVERAGE: Record<Coverage, string> = { enforced: 'Enforced', partial: 'Partly built', not_built: 'Not built yet', guidance: 'Guidance' };

export interface DisplayRule extends CustomRule {
  status?: RuleStatus;
  coverage?: Coverage;
}

interface RuleRowProps {
  rule: DisplayRule;
  areas: readonly { id: string; title: string }[];
  onSave: ((id: string, edit: RuleEdit) => Promise<void>) | null;
}

function RuleRow({ rule, areas, onSave }: RuleRowProps) {
  const [draft, setDraft] = useState<RuleEdit | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const save = async (): Promise<void> => {
    if (!draft || !onSave) return;
    setBusy(true); setError(null);
    try {
      await onSave(rule.id, draft);
      setDraft(null);
    } catch (e) { setError(e as Error); }
    finally { setBusy(false); }
  };
  return <tr data-testid={`rulebook-rule-${rule.id}`}>
    <td className="td mono align-top">{rule.id}</td>
    <td className="td align-top">{draft ? areas.length ? <select className="input min-w-40" aria-label={`Area for ${rule.id}`} data-testid={`rule-area-${rule.id}`} disabled={busy} value={draft.area} onChange={event => setDraft({ ...draft, area: event.target.value })}>{areas.map(area => <option key={area.id} value={area.id}>{area.title}</option>)}</select> : <input className="input min-w-40" aria-label={`Area for ${rule.id}`} data-testid={`rule-area-${rule.id}`} maxLength={200} disabled={busy} value={draft.area} onChange={event => setDraft({ ...draft, area: event.target.value })} /> : areas.find(area => area.id === rule.area)?.title ?? rule.area}</td>
    <td className="td whitespace-pre-wrap align-top">{draft ? <textarea className="input min-w-72" rows={5} maxLength={4000} aria-label={`Text for ${rule.id}`} data-testid={`rule-text-${rule.id}`} disabled={busy} value={draft.text} onChange={event => setDraft({ ...draft, text: event.target.value })} /> : rule.text}</td>
    <td className="td align-top capitalize">{rule.status ?? 'Custom'}</td>
    <td className="td align-top">{rule.coverage ? <Pill value={rule.coverage} label={RULE_COVERAGE[rule.coverage]} /> : 'Reference only'}</td>
    <td className="td whitespace-pre-wrap align-top text-ink-2">{draft ? <textarea className="input min-w-56" rows={4} maxLength={2000} aria-label={`Notes for ${rule.id}`} data-testid={`rule-note-${rule.id}`} disabled={busy} value={draft.note} onChange={event => setDraft({ ...draft, note: event.target.value })} /> : rule.note || '—'}</td>
    <td className="td align-top">{draft ? <div className="space-y-2"><button className="btn-primary" data-testid={`rule-save-${rule.id}`} disabled={busy || !draft.text.trim() || !draft.area.trim()} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</button><button className="btn-ghost" data-testid={`rule-cancel-${rule.id}`} disabled={busy} onClick={() => { setDraft(null); setError(null); }}>Cancel</button><ErrorNote error={error} /></div> : onSave && <button className="icon-button" aria-label={`Edit rule ${rule.id}`} title="Edit rule" data-testid={`rule-edit-${rule.id}`} onClick={() => { setDraft({ area: rule.area, text: rule.text, note: rule.note }); setError(null); }}><Pencil size={16} /></button>}</td>
  </tr>;
}

export function RulebookRules({ rules, areas, onSave }: { rules: DisplayRule[]; areas: readonly { id: string; title: string }[]; onSave: RuleRowProps['onSave'] }) {
  return <div className="overflow-x-auto"><table className="w-full" data-testid="rulebook-rules-table">
    <thead><tr>{['Rule ID', 'Area', 'Rule', 'Source status', 'Coverage', 'Notes', 'Edit'].map(label => <th key={label} className="th" scope="col">{label}</th>)}</tr></thead>
    <tbody>{rules.map(rule => <RuleRow key={rule.id} rule={rule} areas={areas} onSave={onSave} />)}</tbody>
  </table></div>;
}
