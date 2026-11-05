import { Activity, BarChart3, Bell, Boxes, CircleHelp, Home, LogOut, Menu, Settings2, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useApi } from '../lib/api';
import { signOut, useMe } from '../lib/auth';
import { Logo } from './Logo';
import { Modal } from './ui';
import { ThemeToggle } from './ThemeToggle';

const links = [
  { to: '/', label: 'Home', icon: Home },
  { to: '/agents', label: 'Agents', icon: Boxes },
  { to: '/needs-you', label: 'Needs you', icon: Bell },
  { to: '/activity', label: 'Activity', icon: Activity },
  { to: '/reports', label: 'Reports', icon: BarChart3 },
  { to: '/settings', label: 'Settings', icon: Settings2 },
];

interface SystemStats { gateways: { id: string; healthy: boolean }[] }

export function Shell() {
  const me = useMe();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const { data: stats, error: connectionError, reload } = useApi<SystemStats>('/stats/command-center');
  const { data: waiting, reload: reloadWaiting } = useApi<{ items: unknown[] }>('/approvals?mine=1');
  useEffect(() => { const timer = window.setInterval(() => void reload(), 30_000); return () => window.clearInterval(timer); }, [reload]);
  useEffect(() => { const timer = window.setInterval(() => void reloadWaiting(), 15_000); return () => window.clearInterval(timer); }, [reloadWaiting]);
  const connected = stats !== null && stats.gateways.length > 0 && stats.gateways.every((node) => node.healthy);
  const count = waiting?.items.length ?? 0;

  return (
    <div className="app-layout">
      <a href="#main-content" className="skip-link">Skip to content</a>
      {mobileOpen && <button aria-label="Close navigation overlay" className="nav-overlay" onClick={() => setMobileOpen(false)} />}
      <aside className={`app-sidebar ${mobileOpen ? 'is-open' : ''}`} aria-label="Main navigation">
        <Link to="/" className="brand" onClick={() => setMobileOpen(false)}><span className="brand-mark"><Logo size={28} /></span><strong>signet<span className="text-royal">.</span></strong></Link>
        <nav className="sidebar-navigation">
          {links.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setMobileOpen(false)} className={({ isActive }) => `sidebar-link ${isActive ? 'selected' : ''}`}><Icon size={19} strokeWidth={1.8} /><span>{label}</span>{to === '/needs-you' && count > 0 && <span className="nav-count" data-testid="needs-you-count">{count}</span>}</NavLink>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="connection-status"><span className={`status-dot ${connected && !connectionError ? 'ok' : 'warn'}`} /><span>{connectionError ? 'Status unavailable' : stats ? connected ? 'Safety gateway connected' : 'Gateway needs attention' : 'Checking…'}</span></div>
          <div className="sidebar-user"><div className="min-w-0"><strong>{me.principal.name}</strong><small>{me.tenant.name}</small></div><ThemeToggle /><button className="icon-button" aria-label="Open quick guide" onClick={() => setHelpOpen(true)}><CircleHelp size={16} /></button><button className="icon-button" aria-label="Sign out" onClick={() => void signOut()}><LogOut size={16} /></button></div>
        </div>
      </aside>
      <div className="app-body">
        <button className="icon-button mobile-menu" data-testid="navigation-toggle" aria-label="Open navigation" aria-expanded={mobileOpen} onClick={() => setMobileOpen(!mobileOpen)}>{mobileOpen ? <X size={20} /> : <Menu size={20} />}</button>
        <main id="main-content" className="app-main"><Outlet /></main>
      </div>
      {helpOpen && <Modal title="Your AI, explained simply" onClose={() => setHelpOpen(false)}><div className="space-y-5 text-sm text-ink-2"><p>Signet checks what each AI agent is allowed to do and keeps a record of its requests.</p><div><strong className="text-ink">Governed</strong><p>The agent has an active seal and its requests go through safety checks.</p></div><div><strong className="text-ink">Shadow mode</strong><p>Signet records what it would stop, without stopping normal requests, so you can see the effect first.</p></div><div><strong className="text-ink">Blocked request</strong><p>Signet refused one action. The agent itself keeps running.</p></div><div><strong className="text-ink">Quarantined or killed</strong><p>A quarantined agent needs a review to restart. A killed agent needs a new approval to return.</p></div><div><strong className="text-ink">Usage and cost</strong><p>Costs are estimates from configured model prices, not an invoice.</p></div><button className="btn-primary" onClick={() => setHelpOpen(false)}>Got it</button></div></Modal>}
    </div>
  );
}
