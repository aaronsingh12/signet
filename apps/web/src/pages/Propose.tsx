import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { ApiError, api } from '../lib/api';
import { useMe } from '../lib/auth';

const AUTONOMY = [
  ['L0', 'Suggests only; a human performs every action'],
  ['L1', 'Acts only after a human approves each action'],
  ['L2', 'Acts; a human reviews afterwards'],
  ['L3', 'Acts autonomously within seal limits'],
  ['L4', 'Fully autonomous; can spawn or direct agents'],
];

// Stage 1 Propose, Phase 1 form. The full wizard with Classify (risk score) arrives in Phase 2; here the
// proposer states the tier, and separation of duties already applies at approval.
export function Propose() {
  const me = useMe();
  const nav = useNavigate();
  const [f, setF] = useState({ name: '', handle: '', purpose: '', sponsor: '', tier: 'T3', autonomy_level: 'L2', team: '' });
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const submit = async () => {
    setBusy(true);
    try {
      const a = await api('/agents', {
        method: 'POST',
        body: { ...f, team: f.team.split(',').map((s) => s.trim()).filter(Boolean).map((user) => ({ user, role: 'builder' })) },
      });
      nav(`/agents/${a.id}`);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <PageHeader title="Propose a new agent" subtitle="Stage 1 · Nothing runs unregistered. You become the accountable owner; someone outside the build team approves the seal." />
      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <Card title="Purpose, owners, autonomy">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="label">Agent name</label>
              <input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value, handle: f.handle || '' })} placeholder="Refund Concierge" />
            </div>
            <div>
              <label className="label">Handle (kebab-case, unique)</label>
              <input className="input mono" value={f.handle} onChange={set('handle')} placeholder="refund-concierge" />
            </div>
            <div className="md:col-span-2">
              <label className="label">Business purpose</label>
              <textarea className="input min-h-20" value={f.purpose} onChange={set('purpose')} placeholder="What the agent does, for whom, and why" />
            </div>
            <div>
              <label className="label">Accountable owner</label>
              <input className="input" value={me.principal.id} disabled />
            </div>
            <div>
              <label className="label">Sponsor</label>
              <input className="input" value={f.sponsor} onChange={set('sponsor')} placeholder="ravi.kapoor@northwind.example" />
            </div>
            <div className="md:col-span-2">
              <label className="label">Build team (comma-separated emails; they can never approve this agent)</label>
              <input className="input" value={f.team} onChange={set('team')} placeholder="arjun.mehta@northwind.example" />
            </div>
            <div>
              <label className="label">Risk tier (Classify sets this from the risk score in Phase 2)</label>
              <select className="input" value={f.tier} onChange={set('tier')}>
                <option value="T1">T1 · Critical</option>
                <option value="T2">T2 · High</option>
                <option value="T3">T3 · Moderate</option>
                <option value="T4">T4 · Low</option>
              </select>
            </div>
          </div>
          <div className="mt-5">
            <label className="label">Autonomy</label>
            <div className="grid gap-2 md:grid-cols-5">
              {AUTONOMY.map(([l, d]) => (
                <button key={l} onClick={() => setF({ ...f, autonomy_level: l })} className={`rounded-md border p-2.5 text-left text-xs ${f.autonomy_level === l ? 'border-royal bg-royal-50' : 'border-line hover:bg-canvas'}`}>
                  <div className="text-sm font-semibold">{l}</div>
                  <div className="mt-0.5 text-ink-2">{d}</div>
                </button>
              ))}
            </div>
          </div>
          <div className="mt-5 flex items-center gap-3">
            <button className="btn-primary" disabled={busy || !f.name || !f.handle || !f.purpose || !f.sponsor} onClick={() => void submit()}>
              Submit proposal
            </button>
            <ErrorNote error={error} />
          </div>
        </Card>
        <Card title="Exit gate">
          <ul className="space-y-2 text-sm">
            {[
              ['Owner named (you)', true],
              ['Sponsor named', !!f.sponsor],
              ['Purpose complete', f.purpose.length > 10],
              ['Autonomy level set', !!f.autonomy_level],
              ['Handle is kebab-case', /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(f.handle)],
            ].map(([l, ok]) => (
              <li key={String(l)} className="flex items-center gap-2">
                <span className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] text-white ${ok ? 'bg-ok' : 'bg-slate-300'}`}>✓</span>
                {l}
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-ink-3">After submission, an approver (Security, Risk or the Governance Board, not on the build team) defines the manifest and signs the seal on the agent's page.</p>
        </Card>
      </div>
    </>
  );
}
