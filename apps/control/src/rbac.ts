import type { NextFunction, Request, Response } from 'express';
import { forbidden } from './errors';

// Roles and permissions (BP 14.2). Roles are bundles of fine-grained permissions; IdP groups map to
// roles (tenant setting), so the IdP stays the source of truth for who holds which role.

export const ROLES = [
  'tenant_admin', 'platform_admin', 'governance_board', 'risk_officer', 'security_officer',
  'agent_owner', 'builder', 'approver', 'auditor', 'viewer', 'automation',
] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  'agents.read', 'agents.write', 'certificates.approve', 'identity.bootstrap',
  'ladder.step_up', 'ladder.throttle', 'ladder.quarantine', 'ladder.kill', 'ladder.release', 'circuit_breaker.arm',
  'ledger.read', 'ledger.verify', 'evidence.export', 'evidence.payload.read',
  'tools.manage', 'secrets.manage', 'discovery.read', 'discovery.write', 'detectors.manage',
  'gateways.read', 'tenant.read', 'tenant.admin',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  tenant_admin: ['tenant.read', 'tenant.admin', 'agents.read', 'ledger.read', 'gateways.read'],
  platform_admin: ['agents.read', 'identity.bootstrap', 'tools.manage', 'secrets.manage', 'discovery.read', 'discovery.write', 'detectors.manage', 'ledger.read', 'gateways.read', 'tenant.read'],
  governance_board: ['agents.read', 'certificates.approve', 'ladder.quarantine', 'circuit_breaker.arm', 'ledger.read', 'ledger.verify', 'gateways.read', 'tenant.read'],
  risk_officer: ['agents.read', 'certificates.approve', 'ladder.quarantine', 'ladder.release', 'ledger.read', 'ledger.verify', 'evidence.export', 'discovery.read', 'gateways.read', 'tenant.read'],
  security_officer: [
    'agents.read', 'certificates.approve', 'ladder.step_up', 'ladder.throttle', 'ladder.quarantine', 'ladder.kill', 'ladder.release',
    'circuit_breaker.arm', 'ledger.read', 'ledger.verify', 'evidence.export', 'evidence.payload.read', 'discovery.read', 'discovery.write',
    'detectors.manage', 'gateways.read', 'tenant.read',
  ],
  // Owners act on their own agents only; handlers check ownership (BP 14.2 "kill own agent").
  agent_owner: ['agents.read', 'agents.write', 'identity.bootstrap', 'ladder.quarantine', 'ladder.kill', 'ledger.read'],
  builder: ['agents.read', 'ledger.read'],
  approver: ['agents.read'],
  auditor: ['agents.read', 'ledger.read', 'ledger.verify', 'evidence.export', 'gateways.read'],
  viewer: ['agents.read'],
  automation: ['agents.read', 'agents.write', 'identity.bootstrap', 'ledger.read', 'ledger.verify', 'evidence.export', 'discovery.write'],
};

export const DEFAULT_GROUP_ROLES: Record<string, Role> = {
  'signet-tenant-admins': 'tenant_admin',
  'signet-platform-admins': 'platform_admin',
  'signet-governance-board': 'governance_board',
  'signet-risk-officers': 'risk_officer',
  'signet-security-officers': 'security_officer',
  'signet-agent-owners': 'agent_owner',
  'signet-builders': 'builder',
  'signet-approvers': 'approver',
  'signet-auditors': 'auditor',
  'signet-viewers': 'viewer',
  'signet-automation': 'automation',
};

export interface Principal {
  id: string; // email for people, svc:<client_id> for machines; this is the identity used for separation of duties
  name: string;
  kind: 'human' | 'service';
  roles: Role[];
  permissions: Permission[];
  groups: string[];
  mfa: boolean;
  auth: 'session' | 'bearer';
  auth_time: number | null;
}

export function rolesFor(groups: string[], mapping: Record<string, Role>): Role[] {
  const roles = new Set<Role>();
  for (const g of groups) {
    const role = mapping[g.replace(/^\//, '')];
    if (role) roles.add(role);
  }
  return [...roles];
}

export const permissionsFor = (roles: Role[]): Permission[] => [...new Set(roles.flatMap((r) => ROLE_PERMISSIONS[r]))];

export const principalOf = (res: Response): Principal => res.locals.principal as Principal;

export const can = (p: Principal, perm: Permission) => p.permissions.includes(perm);

// Route guard: the caller needs at least one of the listed permissions.
export const requires = (...perms: Permission[]) => (_req: Request, res: Response, next: NextFunction) => {
  const p = res.locals.principal as Principal | undefined;
  if (!p) return next(forbidden('AUTH', 'sign-in required'));
  if (!perms.some((perm) => can(p, perm))) return next(forbidden('RBAC', `needs permission ${perms.join(' or ')}`));
  next();
};
