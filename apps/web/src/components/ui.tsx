import { X } from 'lucide-react';
import type { ReactNode } from 'react';

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-ink-2">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ title, action, children, className = '', pad = true }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; pad?: boolean }) {
  return (
    <section className={`card ${className}`}>
      {title && (
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </div>
      )}
      <div className={pad ? 'p-4' : ''}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: 'ok' | 'bad' | 'warn' }) {
  const toneCls = tone === 'bad' ? 'text-bad' : tone === 'ok' ? 'text-ok' : tone === 'warn' ? 'text-warn' : 'text-ink-3';
  return (
    <div className="card px-4 py-3">
      <div className="text-xs font-medium text-ink-3">{label}</div>
      <div className="mt-1 text-2xl font-semibold tracking-tight">{value}</div>
      {hint && <div className={`mt-0.5 text-xs ${toneCls}`}>{hint}</div>}
    </div>
  );
}

export function TierChip({ tier }: { tier: string }) {
  const cls = tier === 'T1' ? 'bg-ink text-white' : tier === 'T2' ? 'bg-ink-2 text-white' : tier === 'T3' ? 'bg-slate-300 text-ink' : 'bg-slate-100 text-ink-2';
  return <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] font-semibold ${cls}`}>{tier}</span>;
}

const DECISION: Record<string, string> = {
  allow: 'bg-ok-50 text-ok',
  allow_with_obligations: 'bg-royal-50 text-royal',
  require_approval: 'bg-warn-50 text-warn',
  step_up: 'bg-warn-50 text-warn',
  throttle: 'bg-warn-50 text-warn',
  deny: 'bg-bad-50 text-bad',
  quarantine: 'bg-bad-50 text-bad',
  kill: 'bg-bad text-white',
  taint: 'bg-warn-50 text-warn',
  would_taint: 'bg-slate-100 text-ink-2',
  none: 'bg-slate-100 text-ink-2',
  // ladder levels
  active: 'bg-ok-50 text-ok',
  step_up_level: 'bg-warn-50 text-warn',
  throttled: 'bg-warn-50 text-warn',
  quarantined: 'bg-bad-50 text-bad',
  killed: 'bg-bad text-white',
  sealed: 'bg-ok-50 text-ok',
  proposed: 'bg-slate-100 text-ink-2',
};

export function Pill({ value, label }: { value: string | null | undefined; label?: string }) {
  if (!value) return <span className="text-ink-3">—</span>;
  return <span className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-semibold ${DECISION[value] ?? 'bg-slate-100 text-ink-2'}`}>{label ?? value.replace(/_/g, ' ')}</span>;
}

export const LEVEL_LABEL: Record<string, string> = { step_up: 'L2 Step-up', throttled: 'L3 Throttle', quarantined: 'L4 Quarantine', killed: 'L5 Kill', active: 'Released' };

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="mono text-ink-2" title={title}>
      {children}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-4 py-8 text-center text-sm text-ink-3">{children}</div>;
}

export function ErrorNote({ error }: { error: { rule?: string; message: string } | null }) {
  if (!error) return null;
  return (
    <div className="rounded-md border border-bad/30 bg-bad-50 px-3 py-2 text-sm text-bad">
      {error.rule && <span className="mono mr-2 font-semibold">{error.rule}</span>}
      {error.message}
    </div>
  );
}

export function Modal({ title, onClose, children, width = 'max-w-xl' }: { title: ReactNode; onClose: () => void; children: ReactNode; width?: string }) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-ink/40 p-6 pt-20" onMouseDown={onClose}>
      <div className={`card w-full ${width}`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 className="text-base font-semibold">{title}</h2>
          <button className="text-ink-3 hover:text-ink" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(120px,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-ink-3">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs({ tabs, active, onChange }: { tabs: { id: string; label: ReactNode }[]; active: string; onChange: (id: string) => void }) {
  return (
    <div className="mb-4 flex gap-1 border-b border-line">
      {tabs.map((t) => (
        <button key={t.id} onClick={() => onChange(t.id)} className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium ${active === t.id ? 'border-royal text-royal' : 'border-transparent text-ink-2 hover:text-ink'}`}>
          {t.label}
        </button>
      ))}
    </div>
  );
}
