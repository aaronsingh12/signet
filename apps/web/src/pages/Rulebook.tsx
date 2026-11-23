import { useState } from 'react';
import { RULEBOOK, RULEBOOK_AREAS, type CustomRule, type CustomRulebook, type RulebookRule, type RuleEdit } from '@signet/core/rulebook';
import { parseCsv, parseXlsx, type SheetRows } from '@signet/core/sheet';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { api, useApi } from '../lib/api';
import { RulebookRules, RULE_COVERAGE } from '../components/RulebookRules';
import { useCan } from '../lib/auth';

/** Read explicit spreadsheet columns without dropping incomplete or duplicate rules. */
function rulesFromSheet(rows: SheetRows): CustomRule[] {
  const headers = (rows[0] ?? []).map(value => value.trim().toLowerCase());
  for (const name of ['id', 'area', 'text']) {
    if (headers.filter(header => header === name).length !== 1) throw new Error(`The worksheet must have exactly one "${name}" column in its first row.`);
  }
  const rules = rows.slice(1).filter(row => row.some(value => value.trim())).map((row, index) => {
    const cell = (name: string): string => (row[headers.indexOf(name)] ?? '').trim();
    const rule: CustomRule = { id: cell('id'), area: cell('area'), text: cell('text'), note: cell('note') };
    if (!rule.id || !rule.area || !rule.text) throw new Error(`Row ${index + 2}: id, area and text are required.`);
    if (rule.id.length > 100 || rule.area.length > 200 || rule.text.length > 4000 || rule.note.length > 2000) throw new Error(`Row ${index + 2}: maximum lengths are id 100, area 200, text 4000 and note 2000 characters.`);
    return rule;
  });
  if (!rules.length || rules.length > 500) throw new Error('A rulebook must contain between 1 and 500 rules.');
  const ids = rules.map(rule => rule.id.toLowerCase());
  const duplicate = ids.find((id, index) => ids.indexOf(id) !== index);
  if (duplicate) throw new Error(`Duplicate rule ID: ${duplicate}. Each rule must have a unique ID.`);
  return rules;
}

function RuleTable({ rules }: { rules: CustomRule[] }) {
  return <div className="overflow-x-auto"><table className="w-full" data-testid="custom-rulebook-table">
    <thead><tr>{['Rule ID', 'Area', 'Rule', 'Notes'].map(label => <th className="th" key={label} scope="col">{label}</th>)}</tr></thead>
    <tbody>{rules.map(rule => <tr key={rule.id}><td className="td mono align-top">{rule.id}</td><td className="td align-top">{rule.area}</td><td className="td whitespace-pre-wrap align-top">{rule.text}</td><td className="td whitespace-pre-wrap align-top text-ink-2">{rule.note || '—'}</td></tr>)}</tbody>
  </table></div>;
}

function RulebookUpload({ onSaved }: { onSaved: (book: CustomRulebook) => void }) {
  const [sheets, setSheets] = useState<{ name: string; rows: SheetRows }[]>([]);
  const [sheet, setSheet] = useState(0);
  const [name, setName] = useState('');
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const selectSheet = (rows: SheetRows): void => {
    setRules([]);
    setError(null);
    try { setRules(rulesFromSheet(rows)); } catch (e) { setError(e as Error); }
  };
  const read = async (file: File): Promise<void> => {
    setBusy(true); setRules([]); setSheets([]); setError(null);
    try {
      if (!/\.(xlsx|csv)$/i.test(file.name)) throw new Error('Upload an Excel .xlsx or CSV file. Convert older .xls files to .xlsx first.');
      if (file.size > 5 * 1024 * 1024) throw new Error('The spreadsheet exceeds 5 MB. Upload a smaller workbook.');
      const parsed = /\.xlsx$/i.test(file.name) ? await parseXlsx(await file.arrayBuffer()) : [{ name: file.name, rows: parseCsv(await file.text()) }];
      setSheets(parsed); setSheet(0); setName(file.name.replace(/\.(xlsx|csv)$/i, '').slice(0, 200));
      selectSheet(parsed[0]?.rows ?? []);
    } catch (e) { setError(e as Error); }
    finally { setBusy(false); }
  };
  const save = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      const body = { name: name.trim(), rules };
      if (new Blob([JSON.stringify(body)]).size > 950_000) throw new Error('The imported rules exceed the API request limit. Split them into smaller rulebooks.');
      const book = await api<CustomRulebook>('/rulebooks', { method: 'POST', body });
      setRules([]); setSheets([]); setName(''); onSaved(book);
    } catch (e) { setError(e as Error); }
    finally { setBusy(false); }
  };
  return <Card title="Upload a custom rulebook" className="mb-5">
    <p className="mb-3 text-sm text-ink-2">Upload Excel (.xlsx) or CSV, with one rule per row. Required headers: <code>id, area, text</code>. Optional header: <code>note</code>. Up to 500 rules and 5 MB per file.</p>
    <p className="mb-3 text-sm text-ink-2">Custom rulebooks are saved for reference and review. Uploading does not activate enforcement or replace Signet’s default safety rules.</p>
    <a className="btn-ghost mb-3" data-testid="rulebook-template" download="rulebook-template.csv" href={`data:text/csv;charset=utf-8,${encodeURIComponent('id,area,text,note\r\nCUSTOM-01,Data,Require approval before exporting customer data,Internal policy\r\n')}`}>Download Excel-compatible CSV template</a>
    <div className="mb-3 flex flex-wrap items-end gap-3">
      <label className="text-sm">Spreadsheet<input className="input mt-1" type="file" accept=".xlsx,.csv" data-testid="rulebook-upload" disabled={busy} onChange={event => { const file = event.target.files?.[0]; if (file) void read(file); event.target.value = ''; }} /></label>
      {sheets.length > 1 && <label className="text-sm">Worksheet<select className="input mt-1" data-testid="rulebook-sheet" value={sheet} disabled={busy} onChange={event => { const index = Number(event.target.value); setSheet(index); selectSheet(sheets[index]!.rows); }}>{sheets.map((item, index) => <option key={index} value={index}>{item.name}</option>)}</select></label>}
      {sheets.length > 0 && <label className="text-sm">Rulebook name<input className="input mt-1" data-testid="rulebook-name" value={name} maxLength={200} disabled={busy} onChange={event => setName(event.target.value)} /></label>}
    </div>
    <ErrorNote error={error} />
    {rules.length > 0 && <><h3 className="my-3 font-semibold">Preview · {rules.length} rules</h3><RuleTable rules={rules} /><button className="btn-primary mt-3" data-testid="rulebook-save" disabled={busy || !name.trim()} onClick={() => void save()}>{busy ? 'Saving…' : 'Save custom rulebook'}</button></>}
    {busy && !rules.length && <p role="status" className="text-sm">Reading spreadsheet…</p>}
  </Card>;
}

export function Rulebook() {
  const can = useCan();
  const { data, error, loading, setData } = useApi<{ items: CustomRulebook[]; default_rules: RulebookRule[] }>('/rulebooks', []);
  const [selected, setSelected] = useState('default');
  const [query, setQuery] = useState('');
  const [area, setArea] = useState('');
  const [coverage, setCoverage] = useState('');
  const [message, setMessage] = useState('');
  const book = data?.items.find(item => item.id === selected);
  const defaultBook = selected === 'default';
  const areas = defaultBook ? RULEBOOK_AREAS.map(item => ({ id: item.id, title: item.title })) : [...new Set(book?.rules.map(rule => rule.area) ?? [])].map(value => ({ id: value, title: value }));
  const search = query.trim().toLowerCase();
  const matches = (rule: { id: string; area: string; text: string; note?: string }): boolean => (!area || rule.area === area) && [rule.id, rule.area, rule.text, rule.note ?? ''].some(value => value.toLowerCase().includes(search));
  const defaults = (data?.default_rules ?? []).filter(rule => matches(rule) && (!coverage || rule.coverage === coverage));
  const custom = book?.rules.filter(matches) ?? [];
  const saveRule = async (ruleId: string, edit: RuleEdit): Promise<void> => {
    const saved = await api<RuleEdit>(`/rulebooks/${encodeURIComponent(selected)}/rules/${encodeURIComponent(ruleId)}`, { method: 'PUT', body: edit });
    setData(current => current ? {
      ...current,
      default_rules: selected === 'default' ? current.default_rules.map(rule => rule.id === ruleId ? { ...rule, ...saved } : rule) : current.default_rules,
      items: current.items.map(item => item.id === selected ? { ...item, rules: item.rules.map(rule => rule.id === ruleId ? { id: rule.id, ...saved } : rule) } : item),
    } : null);
    setMessage(`Saved rule ${ruleId}.`);
  };
  return <>
    <PageHeader title="Rulebook" subtitle="Read Signet’s default rules and manage your organisation’s custom rulebooks." />
    <p className="mb-4 text-sm text-ink-2">Edits update this reference rulebook only. Runtime safety policy stays governed by the enforcement code; coverage labels describe the built-in implementation.</p>
    {can('tenant.admin') && data && <RulebookUpload onSaved={saved => { setData(current => current ? { ...current, items: [saved, ...current.items] } : null); setSelected(saved.id); setArea(''); setCoverage(''); setQuery(''); setMessage(`Saved ${saved.name} with ${saved.rules.length} rules.`); }} />}
    {message && <p className="mb-3 text-sm text-ok" role="status">{message}</p>}
    <ErrorNote error={error} />
    {loading && <p role="status" className="mb-3 text-sm text-ink-2">Loading custom rulebooks…</p>}
    <Card className="mb-4">
      <label className="text-sm font-medium">Rulebook<select className="input mt-1" data-testid="rulebook-select" value={selected} onChange={event => { setSelected(event.target.value); setArea(''); setCoverage(''); setQuery(''); }}><option value="default">Signet default · {RULEBOOK.version}</option>{data?.items.map(item => <option key={item.id} value={item.id}>{item.name} · Custom</option>)}</select></label>
      <h2 className="mt-4 font-semibold">{defaultBook ? `${RULEBOOK.title} · ${RULEBOOK.version}` : book?.name}</h2>
      <p className="mt-1 text-sm text-ink-2">{defaultBook ? `${data?.default_rules.length ?? 0} rules · Published ${RULEBOOK.date}. ${RULEBOOK.basis}` : book ? `${book.rules.length} rules · Uploaded ${new Date(book.created_at).toLocaleString()} by ${book.created_by}. Reference only; not enforced.` : ''}</p>

      <div className="mt-4 flex flex-wrap gap-3">
        <input className="input max-w-xs" aria-label="Search rules" data-testid="rulebook-search" placeholder="Search rule ID, text or notes" value={query} onChange={event => setQuery(event.target.value)} />
        <select className="input max-w-xs" aria-label="Filter by area" data-testid="rulebook-area" value={area} onChange={event => setArea(event.target.value)}><option value="">All areas</option>{areas.map(item => <option key={item.id} value={item.id}>{item.title}</option>)}</select>
        {defaultBook && <select className="input max-w-xs" aria-label="Filter by coverage" data-testid="rulebook-coverage" value={coverage} onChange={event => setCoverage(event.target.value)}><option value="">All coverage</option>{Object.entries(RULE_COVERAGE).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select>}
      </div>
    </Card>
    <Card pad={false}>
      <p className="p-4 text-sm text-ink-2" role="status">{defaultBook ? defaults.length : custom.length} rules shown</p>
      <RulebookRules key={selected} rules={defaultBook ? defaults.map(rule => ({ ...rule, note: rule.note ?? '' })) : custom} areas={defaultBook ? RULEBOOK_AREAS : []} onSave={can('tenant.admin') && data ? saveRule : null} />
      {(defaultBook ? defaults.length : custom.length) === 0 && <p className="p-4 text-sm text-ink-2">No rules match these filters.</p>}
    </Card>
  </>;
}
