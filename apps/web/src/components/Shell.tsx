import { Activity, Bell, BookLock, Boxes, Cable, ClipboardCheck, ChevronRight, CircleHelp, KeyRound, LayoutDashboard, LogOut, Menu, Plug, Radar, ScrollText, Settings2, ShieldCheck, SlidersHorizontal, Users, Wrench, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { api, useApi } from '../lib/api';
import { signOut, useMe } from '../lib/auth';
import { ago } from '../lib/format';
import { Logo } from './Logo';
import { Modal } from './ui';

const mainLinks = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/agents', label: 'AI agents', icon: Boxes },
  { to: '/approvals', label: 'Approvals', icon: ClipboardCheck },
  { to: '/live', label: 'Live activity', icon: Activity },
  { to: '/enforcement', label: 'Safety center', icon: ShieldCheck },
  { to: '/ledger', label: 'Activity history', icon: ScrollText },
];
const settingsLinks = [
  { to: '/discovery', label: 'Discovered agents', icon: Radar },
  { to: '/settings/agents', label: 'Agent settings', icon: Boxes },
  { to: '/controls', label: 'Control library', icon: BookLock },
  { to: '/connectors', label: 'Service connectors', icon: Cable },
  { to: '/policies', label: 'Safety rules', icon: SlidersHorizontal },
  { to: '/tools', label: 'Tools & credentials', icon: Wrench },
  { to: '/plugins', label: 'Connections', icon: Plug },
  { to: '/tenant', label: 'Workspace & access', icon: Users },
];

interface SystemStats { gateways: { id: string; healthy: boolean }[] }

export function Shell() {
  const me = useMe();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(settingsLinks.some((item) => location.pathname.startsWith(item.to)));
  const [helpOpen, setHelpOpen] = useState(false);
  const { data: stats, error: connectionError, reload } = useApi<SystemStats>('/stats/command-center');
  useEffect(() => { const timer = window.setInterval(() => void reload(), 30_000); return () => window.clearInterval(timer); }, [reload]);
  const connected = stats !== null && stats.gateways.length > 0 && stats.gateways.every((node) => node.healthy);
  const section = [...mainLinks, ...settingsLinks].find((item) => item.to !== '/' && location.pathname.startsWith(item.to))?.label ?? 'Overview';
  const initials = me.principal.name.slice(0, 2).toUpperCase();
  return (
    <div className="app-layout">
      <a href="#main-content" className="skip-link">Skip to content</a>
      {mobileOpen && <button aria-label="Close navigation overlay" className="nav-overlay" onClick={() => setMobileOpen(false)} />}
      <aside className={`app-sidebar ${mobileOpen ? 'is-open' : ''}`} aria-label="Main navigation">
        <Link to="/" className="brand" onClick={() => setMobileOpen(false)}><span className="brand-mark"><Logo size={31} /></span><span><strong>signet<span className="text-royal">.</span></strong><small>AI, under your control</small></span></Link>
        <div className="workspace-label"><span className="workspace-avatar">{me.tenant.name.slice(0, 1)}</span><div><strong>{me.tenant.name}</strong><small>Your workspace</small></div></div>
        <nav className="sidebar-navigation">
          <div className="nav-caption">WORKSPACE</div>
          {mainLinks.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/' || to === '/agents'} onClick={() => setMobileOpen(false)} className={({ isActive }) => `sidebar-link ${isActive ? 'selected' : ''}`}><Icon size={19} strokeWidth={1.7} /><span>{label}</span></NavLink>)}
          <div className="nav-caption mt-8">MANAGE</div>
          <button className="sidebar-link w-full" data-testid="settings-toggle" aria-expanded={settingsOpen} aria-controls="settings-navigation" onClick={() => setSettingsOpen(!settingsOpen)}><Settings2 size={19} strokeWidth={1.7} /><span>Settings</span><ChevronRight size={15} className={`ml-auto transition ${settingsOpen ? 'rotate-90' : ''}`} /></button>
          {settingsOpen && <div id="settings-navigation" className="settings-navigation">{settingsLinks.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} onClick={() => setMobileOpen(false)} className={({ isActive }) => `sidebar-link ${isActive ? 'selected' : ''}`}><Icon size={16} /><span>{label}</span></NavLink>)}</div>}
        </nav>
        <div className="sidebar-bottom"><div className="connection-status"><span className={`status-dot ${connected && !connectionError ? 'ok' : 'warn'}`} /><span>{connectionError ? 'Connection check unavailable' : stats ? connected ? 'Safety gateway connected' : 'Gateway needs attention' : 'Checking connection…'}</span></div></div>
      </aside>
      <div className="app-body">
        <header className="app-header">
          <button className="icon-button mobile-menu" data-testid="navigation-toggle" aria-label="Open navigation" aria-expanded={mobileOpen} onClick={() => setMobileOpen(!mobileOpen)}>{mobileOpen ? <X size={20} /> : <Menu size={20} />}</button>
          <div className="header-breadcrumb"><span>Workspace</span><ChevronRight size={14} /><strong>{section}</strong></div>
          <div className="header-actions"><Notifications /><span className="header-safety"><ShieldCheck size={15} /> Independent AI governance</span><button className="icon-button" aria-label="Open quick guide" onClick={() => setHelpOpen(true)}><CircleHelp size={19} /></button><div className="profile-avatar">{initials}</div><div className="profile-info"><strong>{me.principal.name}</strong><small>{me.principal.roles.includes('tenant_admin') ? 'Administrator' : 'Workspace member'}</small></div><button className="icon-button" aria-label="Sign out" onClick={() => void signOut()}><LogOut size={17} /></button></div>
        </header>
        <main id="main-content" className="app-main"><Outlet /></main>
        <footer className="app-footer"><span>Signet · A clearer view of your AI</span><span><ShieldCheck size={13} /> Every action has a record</span></footer>
      </div>
      {helpOpen && <Modal title="Your AI, explained simply" onClose={() => setHelpOpen(false)}><div className="space-y-5 text-sm text-ink-2"><p>Signet checks what each AI agent is allowed to do and keeps a record of its requests.</p><div><strong className="text-ink">Governed</strong><p>The agent has an active approval certificate. Its requests still go through safety checks.</p></div><div><strong className="text-ink">Blocked request</strong><p>Signet refused a particular action. This does not always mean the entire agent has stopped.</p></div><div><strong className="text-ink">Paused or stopped</strong><p>A paused agent needs review. A permanently stopped agent needs a new approval process before returning.</p></div><div><strong className="text-ink">Usage & cost</strong><p>Charts show the last 24 hours of recorded requests. Costs are estimates from configured model prices, not an invoice.</p></div><button className="btn-primary" onClick={() => setHelpOpen(false)}>Got it</button></div></Modal>}
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
                  <div className="text-[11px] font-normal text-ink-3">{n.kind} Â· {ago(n.created_at)}</div>
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
