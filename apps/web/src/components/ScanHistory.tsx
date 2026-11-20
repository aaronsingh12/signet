import { useEffect, useState } from 'react';
import { parseScanHistory, SCAN_SOURCES, type ScanHistory as ScanHistoryResponse, type ScanCheck, type ScanSource } from '../../../../packages/core/src/scan-history';
import { api } from '../lib/api';
import { Card, Empty, ErrorNote, Mono, Pill } from './ui';

const CHECK_LABELS: Record<ScanCheck, string> = { passed: 'Passed', blocked: 'Blocked', flagged: 'Flagged', unavailable: 'Unavailable', not_run: 'Not run', not_recorded: 'Not recorded' };
const RESULT_LABELS: Record<ScanHistoryResponse['items'][number]['result'], string> = { completed: 'Completed', blocked: 'Blocked by Signet', flagged: 'Flagged · action requested', review: 'Needs review', failed: 'Service error' };
const SOURCE_LABELS: Record<ScanSource, string> = { gateway_model: 'Gateway model · safety', gateway_tool: 'Gateway tool · DLP', servicenow_guardian: 'Guardian submitted content', servicenow_native: 'ServiceNow native block' };

/** Keep a paginated, automatically refreshed view of gateway checks without fetching chat content. */
export function ScanHistory({ agentId }: { agentId: string }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [source, setSource] = useState<ScanSource | null>(null);
  const path = `/agents/${agentId}/scans?limit=25${cursor === null ? '' : `&cursor=${encodeURIComponent(cursor)}`}${source === null ? '' : `&source=${source}`}`;
  const [data, setData] = useState<ScanHistoryResponse | null>(null);
  const [failure, setFailure] = useState<Error | null>(null);
  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const refresh = async (): Promise<void> => {
      try {
        const result = parseScanHistory(await api<ScanHistoryResponse>(path));
        if (active) { setData(result); setFailure(null); }
      } catch (cause) {
        if (!(cause instanceof Error)) throw cause;
        if (active) setFailure(cause);
      } finally {
        if (active) timer = setTimeout(() => void refresh(), 10_000);
      }
    };
    setData(null);
    void refresh();
    return () => { active = false; clearTimeout(timer); };
  }, [path, setData]);
  return (
    <div className="mt-6" data-testid="scan-history">
      <Card title="Scan history" action={<span className="text-xs text-ink-3">Updates every 10 seconds</span>}>
        <p className="mb-3 text-xs text-ink-3">Model safety, tool DLP, Guardian submitted-content reviews and confirmed native blocks. Guardian input/reply stages are not supplied; its verdict appears under Content check. Tool DLP passes do not assert completion of asynchronous injection scoring. Times use {Intl.DateTimeFormat().resolvedOptions().timeZone}.</p>
        <label className="label mb-3" htmlFor={`scan-source-${agentId}`}>Source<select id={`scan-source-${agentId}`} data-testid="scan-history-source" className="input" value={source ?? ''} onChange={event => { setSource(SCAN_SOURCES.find(value => value === event.target.value) ?? null); setCursor(null); }}><option value="">All sources</option>{SCAN_SOURCES.map(value => <option key={value} value={value}>{SOURCE_LABELS[value]}</option>)}</select></label>
        <ErrorNote error={failure} />
        {!data && !failure && <p role="status" className="text-sm text-ink-3">Loading scan history...</p>}
        {data && !data.items.length && <Empty>No checks recorded for this source yet.</Empty>}
        {data && data.items.length > 0 && <div className="overflow-x-auto"><table className="w-full" data-testid="scan-history-table">
          <thead><tr>{['Date and time', 'Source / scope', 'Result', 'Input check', 'Reply check', 'Content check', 'Reference'].map((label) => <th key={label} className="th">{label}</th>)}</tr></thead>
          <tbody>{data.items.map((scan) => <tr key={scan.record_id} data-testid="scan-history-row" data-source={scan.source} data-record-id={scan.record_id}>
            <td className="td whitespace-nowrap text-xs"><time dateTime={scan.scanned_at}>{new Date(scan.scanned_at).toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short' })}</time></td>
            <td className="td text-xs">{SOURCE_LABELS[scan.source]}</td>
            <td className="td"><Pill value={scan.result === 'completed' ? 'allow' : scan.result === 'blocked' ? 'deny' : 'require_approval'} label={scan.source === 'servicenow_native' ? 'Blocked by ServiceNow' : scan.source === 'servicenow_guardian' && scan.result === 'completed' ? 'Reviewed · clear' : RESULT_LABELS[scan.result]} /></td>
            <td className="td text-xs" data-testid="scan-input-check" data-check={scan.input_check}>{scan.source.startsWith('servicenow_') ? 'Stage not supplied' : CHECK_LABELS[scan.input_check]}</td><td className="td text-xs" data-testid="scan-reply-check" data-check={scan.output_check}>{scan.source.startsWith('servicenow_') ? 'Stage not supplied' : CHECK_LABELS[scan.output_check]}</td>
            <td className="td text-xs" data-testid="scan-content-check" data-check={scan.content_check}>{scan.content_check === 'not_run' ? '—' : CHECK_LABELS[scan.content_check]}</td>
            <td className="td text-xs"><Mono>{scan.record_id}</Mono></td>
          </tr>)}</tbody>
        </table></div>}
        <div className="mt-3 flex justify-end gap-2">
          {cursor !== null && <button className="btn-ghost" data-testid="scan-history-latest" onClick={() => setCursor(null)}>Latest scans</button>}
          {data?.next_cursor && <button className="btn-ghost" data-testid="scan-history-older" onClick={() => setCursor(data.next_cursor)}>Older scans</button>}
        </div>
      </Card>
    </div>
  );
}
