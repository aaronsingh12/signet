import {
  Activity, Bell, BookLock, Boxes, Cable, ClipboardCheck, Cpu, FileSearch, Gauge, KeyRound, LayoutDashboard, LogOut, Plus, Radar, ScrollText, ShieldAlert, SlidersHorizontal, Users, Wrench,
} from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { api, useApi } from '../lib/api';
import { ago } from '../lib/format';
import { ROLE_LABEL, signOut, useMe } from '../lib/auth';
import { Logo } from './Logo';

interface Item {
  to: string;
  label: string;
  icon: ReactNode;
  phase?: string; // screens that arrive in a later phase are shown, disabled, with their phase
}

const NAV: { section: string; items: Item[] }[] = [
  { section: 'Home', items: [{ to: '/', label: 'Command Center', icon: <LayoutDashboard size={16} /> }] },
  {
    section: 'Agents',
    items: [
      { to: '/agents', label: 'Agent Registry', icon: <Boxes size={16} /> },
      { to: '/agents/new', label: 'Propose agent', icon: <Plus size={16} /> },
      { to: '/discovery', label: 'Discovery Inbox', icon: <Radar size={16} /> },
    ],
  },
  {
    section: 'Governance',
    items: [
      { to: '/approvals', label: 'My Approvals', icon: <ClipboardCheck size={16} /> },
      { to: '/controls', label: 'Control Library', icon: <BookLock size={16} /> },
    ],
  },
  {
    section: 'Runtime',
    items: [
      { to: '/live', label: 'Live Traffic', icon: <Activity size={16} /> },
      { to: '/enforcement', label: 'Enforcement Center', icon: <ShieldAlert size={16} /> },
      { to: '/ledger', label: 'Ledger Explorer', icon: <ScrollText size={16} /> },
    ],
  },
  {
    section: 'Admin',
    items: [
      { to: '/policies', label: 'Policies & detectors', icon: <SlidersHorizontal size={16} /> },
      { to: '/tools', label: 'Tools & secrets', icon: <Wrench size={16} /> },
      { to: '/connectors', label: 'Connectors', icon: <Cable size={16} /> },
      { to: '/tenant', label: 'Tenant & access', icon: <Users size={16} /> },
    ],
  },
];

export function Shell() {
  const me = useMe();
  const { data: stats } = useApi<any>('/stats/command-center');
  const healthy = (stats?.gateways ?? []).filter((g: any) => g.healthy).length;
  const total = (stats?.gateways ?? []).length;
  const initials = me.principal.name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase();
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col bg-shell text-shell-text">
        <div className="flex items-center gap-2.5 px-4 py-4">
          <Logo />
          <div>
            <div className="text-[15px] font-semibold text-white">Signet</div>
            <div className="text-[11px]">{me.tenant.name}</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto px-2 pb-4">
          {NAV.map((g) => (
            <div key={g.section} className="mt-4">
              <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">{g.section}</div>
              {g.items.map((i) =>
                i.phase ? (
                  <div key={i.to} className="flex cursor-not-allowed items-center gap-2 rounded-md px-2 py-1.5 text-[13px] text-slate-600" title={`${i.label} arrives in ${i.phase}`}>
                    {i.icon}
                    <span className="flex-1">{i.label}</span>
                    <span className="rounded bg-shell-2 px-1 text-[9px]">{i.phase}</span>
                  </div>
                ) : (
                  <NavLink key={i.to} to={i.to} end={i.to === '/' || i.to === '/agents'} className={({ isActive }) => `flex items-center gap-2 rounded-md px-2 py-1.5 text-[13px] ${isActive ? 'bg-shell-2 font-medium text-white' : 'hover:bg-shell-2 hover:text-white'}`}>
                    {i.icon}
                    {i.label}
                  </NavLink>
                ),
              )}
            </div>
          ))}
        </nav>
        <div className="border-t border-shell-line px-4 py-3 text-[11px]">
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className={`h-2 w-2 rounded-full ${total && healthy === total ? 'bg-emerald-400' : 'bg-amber-400'}`} />
            {healthy}/{total} gateway nodes healthy
          </div>
          <div className="mt-0.5">
            <Cpu size={11} className="mr-1 inline" />
            gateway p95 {stats?.gateway_p95_ms_24h ?? '—'} ms · dev · single tenant
          </div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-white/95 px-6 backdrop-blur">
          <div className="flex items-center gap-2 text-xs text-ink-3">
            <FileSearch size={14} /> Every action here goes through the public API and is written to the admin ledger.
          </div>
          <div className="ml-auto flex items-center gap-3">
            <Notifications />
            <span className="rounded-md border border-line px-2 py-1 text-xs text-ink-2">
              <Gauge size={12} className="mr-1 inline" />
              Environment: dev
            </span>
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-royal text-xs font-semibold text-white">{initials}</div>
              <div className="leading-tight">
                <div className="text-sm font-medium">{me.principal.name}</div>
                <div className="text-[11px] text-ink-3">{me.principal.roles.map((r) => ROLE_LABEL[r] ?? r).join(' · ') || 'No Signet role'}</div>
              </div>
            </div>
            <button className="btn-ghost" onClick={() => void signOut()} title="Sign out">
              <LogOut size={14} />
            </button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-6 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// The bell: approvals waiting, lifecycle steps, reminders and escalations for me or my roles.
function Notifications() {
  const [open, setOpen] = useState(false);
  const { data, reload } = useApi<any>('/notifications');
  useEffect(() => {
    const t = setInterval(() => void reload(), 15_000);
    return () => clearInterval(t);
  }, [reload]);
  const toggle = async () => {
    setOpen(!open);
    if (!open && data?.unread) {
      await api('/notifications/read', { method: 'POST' }).catch(() => {});
      void reload();
    }
  };
  return (
    <div className="relative">
      <button className="btn-ghost relative" onClick={() => void toggle()} title="Notifications">
        <Bell size={15} />
        {!!data?.unread && <span className="absolute -right-1 -top-1 rounded-full bg-bad px-1.5 text-[10px] font-semibold text-white">{data.unread}</span>}
      </button>
      {open && (
        <div className="card absolute right-0 top-10 z-40 w-96 overflow-hidden" onMouseLeave={() => setOpen(false)}>
          <div className="border-b border-line px-4 py-2 text-sm font-semibold">Notifications</div>
          <ul className="max-h-96 divide-y divide-line overflow-y-auto">
            {(data?.items ?? []).slice(0, 30).map((n: any) => (
              <li key={n.id}>
                <Link to={n.link ?? '#'} onClick={() => setOpen(false)} className={`block px-4 py-2.5 text-sm hover:bg-canvas ${n.read_at ? 'text-ink-2' : 'font-medium'}`}>
                  {n.title}
                  <div className="text-[11px] font-normal text-ink-3">{n.kind} · {ago(n.created_at)}</div>
                </Link>
              </li>
            ))}
            {!data?.items?.length && <li className="px-4 py-6 text-center text-sm text-ink-3">Nothing new.</li>}
          </ul>
        </div>
      )}
    </div>
  );
}

export const KeyIcon = KeyRound;
