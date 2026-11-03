import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api } from './api';

export interface Principal {
  id: string;
  name: string;
  kind: 'human' | 'service';
  roles: string[];
  permissions: string[];
  mfa: boolean;
}

interface Me {
  principal: Principal;
  tenant: { id: string; name: string };
}

const Ctx = createContext<Me | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    api<Me>('/me').then(setMe).catch(() => {});
  }, []);
  if (!me) return <div className="flex h-screen items-center justify-center text-sm text-ink-3">Checking your session…</div>;
  return <Ctx.Provider value={me}>{children}</Ctx.Provider>;
}

export const useMe = () => useContext(Ctx)!;
export const useCan = () => {
  const me = useMe();
  return (perm: string) => me.principal.permissions.includes(perm);
};

export async function signOut() {
  const r = await api<{ redirect: string }>('/auth/logout', { method: 'POST' });
  location.assign(r.redirect);
}

export const ROLE_LABEL: Record<string, string> = {
  tenant_admin: 'Tenant Admin',
  platform_admin: 'Platform Admin',
  governance_board: 'AI Governance Board',
  risk_officer: 'Risk & Compliance Officer',
  security_officer: 'Security Officer',
  agent_owner: 'Agent Owner',
  builder: 'Builder',
  approver: 'Approver',
  auditor: 'Auditor',
  viewer: 'Viewer',
  automation: 'Automation',
};
