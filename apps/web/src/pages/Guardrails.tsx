import { useMemo, useState, type ReactNode } from 'react';
import type { Guardrail, GuardrailGroupInfo } from '@signet/core/guardrails';
import type { Coverage, RulebookRule } from '@signet/core/rulebook';
import { Card, Empty, ErrorNote, Mono, PageHeader, Stat, TierChip } from '../components/ui';
import { useApi } from '../lib/api';

// The Guardrails page (/guardrails): every check Signet enforces, from the one catalogue in @signet/core, with the
// detector modes and limits in force now (GET /guardrails), and the Rulebook with what is built.

type Status = 'enforced' | 'shadow' | 'off' | 'findings_only';
type Item = Guardrail & { status: Status; live: string | null };
type Rule = RulebookRule & { guardrails: string[] };
interface GuardrailsView {
  groups: GuardrailGroupInfo[];
  pipeline: { n: number; name: string; what: string }[];
  items: Item[];
  counts: { total: number; enforced: number; shadow: number; off: number };
  gateways: { reporting: number; live: number; consistent: boolean };
  rulebook: {
    title: string; version: string; date: string; basis: string;
    areas: { id: string; title: string }[];
    rules: Rule[];
    decisions: { id: string; question: string; decided: string }[];
    counts: { total: number; enforced: number; partial: number; not_built: number; guidance: number };
  };
}

const COVERAGE: Record<Coverage, { label: string; cls: string }> = {
  enforced: { label: 'Enforced', cls: 'bg-ok-50 text-ok' },
  partial: { label: 'Partly built', cls: 'bg-warn-50 text-warn' },
  not_built: { label: 'Not built yet', cls: 'bg-bad-50 text-bad' },
  guidance: { label: 'Guidance', cls: 'bg-slate-100 text-ink-2' },
};

const EFFECT: Record<string, { label: string; cls: string }> = {
  block: { label: 'Blocks', cls: 'bg-bad-50 text-bad' },
  hold: { label: 'Holds for a person', cls: 'bg-warn-50 text-warn' },
  step_up: { label: 'Extra checks', cls: 'bg-warn-50 text-warn' },
  throttle: { label: 'Slows down', cls: 'bg-warn-50 text-warn' },
  quarantine: { label: 'Pauses agent', cls: 'bg-bad-50 text-bad' },
  kill: { label: 'Stops agent', cls: 'bg-bad text-white' },
  redact: { label: 'Redacts', cls: 'bg-royal-50 text-royal' },
  tokenise: { label: 'Tokenises', cls: 'bg-royal-50 text-royal' },
  modify: { label: 'Adjusts request', cls: 'bg-royal-50 text-royal' },
  detect: { label: 'Detects', cls: 'bg-slate-100 text-ink-2' },
  record: { label: 'Records', cls: 'bg-slate-100 text-ink-2' },
  refuse: { label: 'Refuses change', cls: 'bg-bad-50 text-bad' },
  combine: { label: 'Decides outcome', cls: 'bg-slate-100 text-ink-2' },
  flag: { label: 'Flags', cls: 'bg-warn-50 text-warn' },
};

const STATUS: Record<Status, { label: string; cls: string; hint: string }> = {
  enforced: { label: 'Enforced', cls: 'bg-ok-50 text-ok', hint: 'Active on every matching request' },
  shadow: { label: 'Shadow', cls: 'bg-warn-50 text-warn', hint: 'Detector scores and records only; T1/T2 allows are held for a person until it is promoted (RB-INV-06)' },
  off: { label: 'Off', cls: 'bg-slate-100 text-ink-2', hint: 'Detector is switched off or not deployed; the rules decide alone' },
  findings_only: { label: 'Findings only', cls: 'bg-royal-50 text-royal', hint: 'Runs offline and reports to people; never changes a decision' },
};

const Chip = ({ cls, children, title }: { cls: string; children: ReactNode; title?: string }) => (
  <span title={title} className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold ${cls}`}>{children}</span>
);

export function Guardrails() {
  const { data, error } = useApi<GuardrailsView>('/guardrails');
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState<string>('');
  const [step, setStep] = useState<number | null>(null);
  const [status, setStatus] = useState<string>('');
  const [open, setOpen] = useState<string | null>(null);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.items ?? []).filter((g) =>
      (!group || g.group === group) &&
      (step === null || g.step === step) &&
      (!status || g.status === status) &&
      (!q || [g.name, g.what, g.live ?? '', g.source, ...g.rule_ids, ...(g.rulebook ?? [])].some((s) => s.toLowerCase().includes(q))));
  }, [data, query, group, step, status]);

  const filtered = !!(query || group || status || step !== null);

  return (
    <>
      <PageHeader
        title="Guardrails"
        subtitle="Every check Signet applies to your agents, where it runs and what it does when triggered. Values shown are the ones in force now."
      />
      <ErrorNote error={error} />
      {!data && !error && <Card><p className="text-sm text-ink-3">Loading guardrails…</p></Card>}
      {data && (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Guardrails" value={data.counts.total} hint="in one catalogue" />
            <Stat label="Enforced" value={data.counts.enforced} tone="ok" hint="active now" />
            <Stat label="Detectors in shadow" value={data.counts.shadow} tone={data.counts.shadow ? 'warn' : undefined} hint="scoring, not deciding" />
            <Stat label="Detectors off" value={data.counts.off} tone={data.counts.off ? 'warn' : undefined} hint="rules decide alone" />
          </div>

          <Card title="How Signet decides" className="mb-4">
            <div className="grid gap-3 text-sm md:grid-cols-3">
              <div><h3 className="font-semibold">Tier 0: rules</h3><p className="mt-1 text-ink-2">Code and policy compiled from the agent’s seal. The only tier that can allow an action. Runs inline on every request.</p></div>
              <div><h3 className="font-semibold">Tier 1: detectors</h3><p className="mt-1 text-ink-2">Small classifiers and baselines. They can only add caution: hold, step-up or pause. A detector alone never stops an agent.</p></div>
              <div><h3 className="font-semibold">Tier 2: evaluator</h3><p className="mt-1 text-ink-2">A larger model reviewing samples offline. Produces findings for people and never changes a decision.</p></div>
            </div>
            <p className="mt-3 text-xs text-ink-3">The strictest result wins. If a detector is missing, the rules decide alone and T1/T2 actions wait for a person. Every decision is written to the ledger before the agent gets an answer.</p>
          </Card>

          {!data.gateways.consistent && (
            <div className="mb-4 rounded-lg border border-warn bg-warn-50 px-4 py-3 text-sm text-warn" role="alert" data-testid="gateway-config-mismatch">
              Gateway nodes are running different guardrail settings (DLP packs, policy engine or environment). See the values marked “Gateway nodes differ” below, and align the gateways’ configuration.
            </div>
          )}
          {data.gateways.live === 0 && (
            <div className="mb-4 rounded-lg border border-line bg-canvas px-4 py-3 text-sm text-ink-2">
              No gateway node has reported in the last few minutes, so settings that gateways report (DLP packs, policy engine, environment) show the control plane’s own values.
            </div>
          )}
          <Card title={`The ${data.pipeline.length} checks on every request`} className="mb-4" action={step !== null ? <button className="text-xs text-royal hover:underline" onClick={() => setStep(null)}>Show all steps</button> : undefined}>
            <ol className="grid gap-2 sm:grid-cols-2 xl:grid-cols-7">
              {data.pipeline.map((s) => {
                const n = data.items.filter((g) => g.step === s.n).length;
                const active = step === s.n;
                return (
                  <li key={s.n}>
                    <button
                      title={s.what}
                      onClick={() => setStep(active ? null : s.n)}
                      className={`h-full w-full rounded-lg border px-2.5 py-2 text-left text-xs ${active ? 'border-royal bg-royal-50' : 'border-line hover:border-royal'}`}
                    >
                      <div className="font-semibold"><span className="text-ink-3">{s.n}.</span> {s.name}</div>
                      <div className="mt-0.5 text-ink-3">{n} guardrail{n === 1 ? '' : 's'}</div>
                    </button>
                  </li>
                );
              })}
            </ol>
          </Card>

          <div className="mb-4 flex flex-wrap items-center gap-2">
            <input className="input max-w-xs" placeholder="Search name, rule ID or text" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search guardrails" />
            <select className="input max-w-[14rem]" value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Filter by group">
              <option value="">All groups</option>
              {data.groups.map((g) => <option key={g.id} value={g.id}>{g.title}</option>)}
            </select>
            <select className="input max-w-[11rem]" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
              <option value="">Any status</option>
              {Object.entries(STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            {filtered && <button className="btn-ghost" onClick={() => { setQuery(''); setGroup(''); setStatus(''); setStep(null); }}>Clear</button>}
            <span className="text-xs text-ink-3">{shown.length} of {data.items.length}</span>
          </div>

          {!shown.length && <Empty>No guardrail matches these filters.</Empty>}
          <div className="grid gap-4">
            {data.groups.map((grp) => {
              const rows = shown.filter((g) => g.group === grp.id);
              if (!rows.length) return null;
              return (
                <Card key={grp.id} pad={false} title={<span>{grp.title} <span className="font-normal text-ink-3">· {rows.length}</span></span>}>
                  <p className="border-b border-line px-4 py-2 text-xs text-ink-2">{grp.summary}</p>
                  <ul className="divide-y divide-line">
                    {rows.map((g) => (
                      <li key={g.key} className="px-4 py-3" data-testid={`guardrail-${g.key}`}>
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <h3 className="text-sm font-semibold">{g.name}</h3>
                              {g.rule_ids.map((id) => <Mono key={id}>{id}</Mono>)}
                            </div>
                            <p className="mt-1 text-sm text-ink-2">{g.what}</p>
                            {g.live && <p className="mt-1 text-xs text-ink"><span className="font-medium">In force: </span>{g.live}</p>}
                          </div>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <Chip cls={STATUS[g.status].cls} title={STATUS[g.status].hint}>{STATUS[g.status].label}</Chip>
                            <Chip cls={EFFECT[g.effect]?.cls ?? 'bg-slate-100 text-ink-2'}>{EFFECT[g.effect]?.label ?? g.effect}</Chip>
                            {g.tiers?.map((t) => <TierChip key={t} tier={t} />)}
                          </div>
                        </div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-3">
                          <span>{g.where === 'gateway' ? `Gateway${g.step ? `, step ${g.step} (${data.pipeline.find((s) => s.n === g.step)?.name})` : ''}` : 'Control plane'}</span>
                          <span>Source: {g.source}</span>
                          <button className="text-royal hover:underline" onClick={() => setOpen(open === g.key ? null : g.key)}>{open === g.key ? 'Hide details' : 'Rulebook and code'}</button>
                        </div>
                        {open === g.key && <Details g={g} rules={data.rulebook.rules} />}
                      </li>
                    ))}
                  </ul>
                </Card>
              );
            })}
          </div>
          <p className="mt-4 text-xs text-ink-3">Rule IDs match the ones recorded on each request in History. Sources: Product &amp; Engineering Blueprint (BP), Decision Architecture (DA), {data.rulebook.title} {data.rulebook.version} (RB).</p>
        </>
      )}
    </>
  );
}

// The Rulebook rules a guardrail implements, word for word, and the code that enforces it.
function Details({ g, rules }: { g: Item; rules: Rule[] }) {
  const linked = rules.filter((r) => g.rule_ids.includes(r.id) || g.rulebook?.includes(r.id));
  return (
    <div className="mt-2 space-y-2 rounded-lg bg-canvas p-3 text-xs">
      {linked.length > 0 && (
        <div>
          <div className="mb-1 font-semibold text-ink-2">Rulebook</div>
          <ul className="space-y-1.5">
            {linked.map((r) => (
              <li key={r.id}>
                <Mono>{r.id}</Mono> <Chip cls={COVERAGE[r.coverage].cls}>{COVERAGE[r.coverage].label}</Chip>
                <span className="ml-1 text-ink-2">{r.text}</span>
                {r.note && <div className="mt-0.5 text-ink-3">{r.note}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <div className="mb-1 font-semibold text-ink-2">Enforced in</div>
        <ul className="space-y-0.5">{g.code.map((c) => <li key={c}><Mono>{c}</Mono></li>)}</ul>
      </div>
    </div>
  );
}
