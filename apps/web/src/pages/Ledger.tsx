import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Card, Empty, KV, Mono, PageHeader, Pill, Tabs } from '../components/ui';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { dlpSummary, hash, time } from '../lib/format';
import { Pipeline } from './LiveTraffic';

const KINDS = [
  ['transaction', 'Transaction'],
  ['lifecycle', 'Lifecycle'],
  ['enforcement', 'Enforcement'],
  ['admin', 'Admin audit'],
] as const;

export function Ledger() {
  const can = useCan();
  const [params] = useSearchParams();
  const [kind, setKind] = useState<string>('transaction');
  const [cursor, setCursor] = useState<string | null>(null);
  const agent = params.get('agent');
  const q = new URLSearchParams({ kind, limit: '50', ...(agent ? { agent } : {}), ...(cursor ? { cursor } : {}) });
  const { data } = useApi<any>(`/ledger/records?${q}`, [kind, cursor, agent]);
  const { data: roots } = useApi<any>('/ledger/roots');
  const [sel, setSel] = useState<any>(null);
  const [proof, setProof] = useState<any>(null);
  const [verify, setVerify] = useState<any>(null);
  const open = async (id: string) => {
    setProof(null);
    setSel(await api(`/ledger/records/${id}`));
  };
  useEffect(() => {
    const r = params.get('record');
    if (r) void open(r);
  }, []);
  return (
    <>
      <PageHeader
        title="Ledger Explorer"
        subtitle="Hash-chained, write-once evidence: record_hash = SHA-256(canonical_json(record) ‖ prev_hash). Each finished UTC day is rolled into a signed Merkle root."
        actions={
          can('evidence.export') && (
            <a className="btn-primary" href="/api/v1/ledger/export">
              Export as .sep
            </a>
          )
        }
      />
      <Tabs active={kind} onChange={(k) => (setKind(k), setCursor(null))} tabs={KINDS.map(([id, label]) => ({ id, label }))} />
      <div className="grid gap-4 xl:grid-cols-[1fr_440px]">
        <Card pad={false}>
          {data?.items?.length ? (
            <table className="w-full">
              <thead><tr>{['Seq', 'Time (UTC)', 'Event', 'Agent', 'Decision', 'DLP', 'Hash'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {data.items.map((r: any) => (
                  <tr key={r.record_id} className={`cursor-pointer hover:bg-canvas ${sel?.record?.record_id === r.record_id ? 'bg-royal-50' : ''}`} onClick={() => void open(r.record_id)}>
                    <td className="td mono">{r.seq}</td>
                    <td className="td mono whitespace-nowrap">{time(r.ts)}</td>
                    <td className="td mono text-xs">{r.data.action_type ?? r.data.event}{r.data.target ? ` · ${r.data.target}` : ''}</td>
                    <td className="td mono text-xs">{r.agent_id ?? '—'}</td>
                    <td className="td"><Pill value={r.data.policy_decision ?? r.data.level} /></td>
                    <td className="td text-xs">{dlpSummary(r.data.dlp_actions)}</td>
                    <td className="td"><Mono>{hash(r.record_hash)}</Mono></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No records of this kind yet.</Empty>
          )}
          <div className="flex justify-end gap-2 px-4 py-3">
            <button className="btn-ghost" disabled={!cursor} onClick={() => setCursor(null)}>Newest</button>
            <button className="btn-ghost" disabled={!data?.next_cursor} onClick={() => setCursor(data.next_cursor)}>Older</button>
          </div>
        </Card>
        <div className="space-y-4">
          <Card title="Record">
            {sel ? (
              <div className="space-y-3">
                <div className="flex gap-1 overflow-x-auto text-[10px]">
                  {sel.neighbours.map((n: any) => (
                    <div key={n.seq} className={`min-w-[96px] rounded border px-2 py-1 ${n.record_id === sel.record.record_id ? 'border-royal bg-royal-50' : 'border-line'}`}>
                      <div className="font-semibold">#{n.seq}</div>
                      <div className="mono">{hash(n.record_hash)}</div>
                      <div className="mono text-ink-3">prev {hash(n.prev_hash)}</div>
                    </div>
                  ))}
                </div>
                <KV rows={[['record_id', <Mono key="i">{sel.record.record_id}</Mono>], ['seq', sel.record.seq], ['ts', sel.record.ts], ['kind', sel.record.kind], ['agent', <Mono key="a">{sel.record.agent_id ?? '—'}</Mono>], ['cert', <Mono key="c">{sel.record.cert_id ?? '—'}</Mono>], ['record_hash', <Mono key="h">{sel.record.record_hash}</Mono>]]} />
                <button className="btn-ghost" onClick={() => void api(`/ledger/records/${sel.record.record_id}/proof`).then(setProof)}>Merkle inclusion proof</button>
                {proof && (
                  <div className="rounded-md bg-canvas p-2 text-xs">
                    Leaf {proof.index} of {proof.tree_size} · {proof.proof.length}-step path to {proof.provisional ? "today's provisional root (signed after 00:00 UTC)" : `the signed root of ${proof.day}`}
                    <div className="mono mt-1 break-all">root {proof.merkle_root}</div>
                  </div>
                )}
                {sel.record.kind === 'transaction' && sel.record.data.steps ? <Pipeline r={sel.record} /> : <pre className="mono max-h-80 overflow-auto rounded-md bg-canvas p-2 text-xs">{JSON.stringify(sel.record.data, null, 2)}</pre>}
              </div>
            ) : (
              <Empty>Select a record.</Empty>
            )}
          </Card>
          <Card title="Verify">
            {can('ledger.verify') ? (
              <>
                <button className="btn-primary" onClick={() => void api('/ledger/verify', { method: 'POST', body: {} }).then(setVerify)}>Verify the whole chain</button>
                {verify && (
                  <div className={`mt-3 rounded-md px-3 py-2 text-sm ${verify.ok && verify.roots_valid ? 'bg-ok-50 text-ok' : 'bg-bad-50 text-bad'}`}>
                    {verify.ok ? `Verified · ${verify.count.toLocaleString()} records · chain intact` : `Broken at seq ${verify.error?.seq}: ${verify.error?.reason}`}
                    <div className="text-xs">{verify.roots_checked} daily roots · signatures {verify.roots_valid ? 'valid' : 'INVALID'} · {verify.ms} ms</div>
                  </div>
                )}
                <p className="mt-2 text-xs text-ink-3">Auditors verify offline with <span className="mono">signet-verify</span> on an exported .sep package, without trusting this server.</p>
              </>
            ) : (
              <Empty>Needs ledger.verify.</Empty>
            )}
          </Card>
          <Card title="Daily roots" pad={false}>
            {roots?.items?.length ? (
              <table className="w-full">
                <tbody>
                  {roots.items.map((r: any) => (
                    <tr key={r.day}>
                      <td className="td mono">{r.day}</td>
                      <td className="td mono">{hash(r.merkle_root)}</td>
                      <td className="td text-xs">{r.count} recs · signed{r.worm ? ' · WORM' : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty>No finished day yet. Roots are signed shortly after 00:00 UTC.</Empty>
            )}
            {roots?.ledger_key && <div className="border-t border-line px-4 py-2 text-xs text-ink-3">Ledger key <Mono>{roots.ledger_key.kid}</Mono> · Ed25519</div>}
          </Card>
        </div>
      </div>
    </>
  );
}
