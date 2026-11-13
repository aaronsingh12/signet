import { useMemo, useState } from 'react';
import { parseCsv, parseXlsx, type SheetRows } from '@signet/core/sheet';
import { Card, ErrorNote } from './ui';
import { ApiError, api } from '../lib/api';

// Spreadsheet importer (BP 9.4): read a CSV or Excel file in the browser, let the person pick the sheet
// and match the columns, preview, then send only the matched rows to Signet. For a "licence needed"
// framework the person records their licence; the content never comes from Signet itself.

const CATEGORIES: [string, string][] = [['other', 'Internal policy or other'], ['ai_risk', 'AI risk'], ['ai_security', 'AI security'], ['ai_law', 'AI law'], ['security', 'Security'], ['privacy', 'Privacy'], ['resilience', 'Resilience'], ['regional', 'Regional']];

export function FrameworkSheetImport({ target, onDone, onCancel }: { target?: { id: string; name: string }; onDone: (message: string) => void; onCancel: () => void }) {
  const [sheets, setSheets] = useState<{ name: string; rows: SheetRows }[]>([]);
  const [sheet, setSheet] = useState(0);
  const [headers, setHeaders] = useState(true);
  const [cols, setCols] = useState({ id: 0, title: 1, description: -1 });
  const [meta, setMeta] = useState({ name: '', version: '', category: 'other', licence: '' });
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);

  const read = async (file: File) => {
    setError(null);
    try {
      const out = /\.xlsx$/i.test(file.name) ? await parseXlsx(await file.arrayBuffer()) : [{ name: file.name, rows: parseCsv(await file.text()) }];
      if (!out.some((s) => s.rows.length)) throw new Error('the file has no rows');
      setSheets(out);
      const first = out.findIndex((s) => s.rows.length);
      setSheet(first);
      guess(out[first]!.rows);
      if (!target && !meta.name) setMeta((m) => ({ ...m, name: file.name.replace(/\.(csv|xlsx)$/i, '') }));
    } catch (e) {
      setError(e as Error);
    }
  };
  // Pre-select columns whose header looks like an ID, a title and a description.
  const guess = (rows: SheetRows) => {
    const h = (rows[0] ?? []).map((x) => x.toLowerCase());
    const find = (re: RegExp, fallback: number) => { const i = h.findIndex((x) => re.test(x)); return i >= 0 ? i : fallback; };
    setCols({ id: find(/\bid\b|ref|number|no\.?$|control$|code/, 0), title: find(/title|name|control name|requirement/, Math.min(1, h.length - 1)), description: find(/desc|text|detail|statement|guidance/, -1) });
  };

  const rows = sheets[sheet]?.rows ?? [];
  const header = headers ? rows[0] ?? [] : [];
  const width = Math.max(0, ...rows.map((r) => r.length));
  const label = (i: number) => `${String.fromCharCode(65 + (i % 26))}${header[i] ? `: ${header[i]}` : ''}`;
  const data = useMemo(() => (headers ? rows.slice(1) : rows).map((r) => ({ external_id: r[cols.id] ?? '', title: cols.title >= 0 ? r[cols.title] ?? '' : '', description: cols.description >= 0 ? r[cols.description] ?? '' : '' })).filter((r) => r.external_id.trim()), [rows, headers, cols]);

  const submit = async () => {
    setBusy(true);
    try {
      const body = target
        ? { framework_id: target.id, licence_confirmation: meta.licence, version: meta.version, rows: data, replace }
        : { name: meta.name, version: meta.version, category: meta.category, rows: data, replace };
      const r = await api<any>('/library/import/sheet', { method: 'POST', body });
      onDone(`Imported ${r.rows} requirements into ${target?.name ?? meta.name} (${r.created} new${r.removed ? `, ${r.removed} removed` : ''}). Link them to Signet Controls, then switch the framework on.`);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };

  const select = (key: 'id' | 'title' | 'description', optional = false) => (
    <select className="input" value={cols[key]} onChange={(e) => setCols({ ...cols, [key]: Number(e.target.value) })}>
      {optional && <option value={-1}>(none)</option>}
      {Array.from({ length: width }, (_, i) => <option key={i} value={i}>{label(i)}</option>)}
    </select>
  );

  return (
    <Card title={target ? `Load your licensed copy of ${target.name}` : 'Import a framework from a spreadsheet'} className="mb-4">
      <ErrorNote error={error as ApiError} />
      <p className="mb-3 text-xs text-ink-3">CSV or Excel (.xlsx). One row per requirement, with at least an ID column. The file is read in your browser; only the matched columns are sent to Signet.</p>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <input type="file" accept=".csv,.xlsx,text/csv" onChange={(e) => e.target.files?.[0] && void read(e.target.files[0])} className="text-sm" />
        {sheets.length > 1 && (
          <label className="text-sm">Sheet{' '}
            <select className="input w-48" value={sheet} onChange={(e) => { setSheet(Number(e.target.value)); guess(sheets[Number(e.target.value)]!.rows); }}>
              {sheets.map((s, i) => <option key={i} value={i}>{s.name} ({s.rows.length} rows)</option>)}
            </select>
          </label>
        )}
        {rows.length > 0 && <label className="text-sm"><input type="checkbox" checked={headers} onChange={(e) => setHeaders(e.target.checked)} /> First row is headers</label>}
      </div>

      {rows.length > 0 && (
        <>
          <div className="mb-3 grid gap-3 md:grid-cols-3">
            <div><label className="label">Requirement ID column</label>{select('id')}</div>
            <div><label className="label">Title column</label>{select('title', true)}</div>
            <div><label className="label">Description column</label>{select('description', true)}</div>
          </div>
          <div className="mb-3 overflow-x-auto">
            <table className="w-full">
              <thead><tr>{['ID', 'Title', 'Description'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {data.slice(0, 5).map((r, i) => (
                  <tr key={i}><td className="td text-xs">{r.external_id}</td><td className="td text-xs">{r.title}</td><td className="td text-xs text-ink-2">{r.description.slice(0, 160)}</td></tr>
                ))}
              </tbody>
            </table>
            <div className="mt-1 text-[11px] text-ink-3">{data.length} requirements with an ID{data.length > 5 ? '; first 5 shown' : ''}.</div>
          </div>
          <div className="mb-3 grid gap-3 md:grid-cols-3">
            {target ? (
              <div className="md:col-span-2"><label className="label">Your licence (order or licence number, date)</label><input className="input" value={meta.licence} onChange={(e) => setMeta({ ...meta, licence: e.target.value })} placeholder="e.g. ISO webstore order 12345, Dec 2026" /></div>
            ) : (
              <>
                <div><label className="label">Framework name</label><input className="input" value={meta.name} onChange={(e) => setMeta({ ...meta, name: e.target.value })} /></div>
                <div><label className="label">Type</label><select className="input" value={meta.category} onChange={(e) => setMeta({ ...meta, category: e.target.value })}>{CATEGORIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
              </>
            )}
            <div><label className="label">Version</label><input className="input" value={meta.version} onChange={(e) => setMeta({ ...meta, version: e.target.value })} placeholder="e.g. 2022" /></div>
          </div>
          <label className="mb-3 block text-sm"><input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} /> Replace: remove requirements from an earlier import that are not in this file</label>
        </>
      )}
      <div className="flex gap-2">
        <button className="btn-primary" disabled={busy || !data.length || (target ? !meta.licence.trim() : !meta.name.trim())} onClick={() => void submit()}>{busy ? 'Importing…' : `Import ${data.length || ''} requirements`}</button>
        <button className="btn-ghost" onClick={onCancel}>Cancel</button>
      </div>
    </Card>
  );
}
