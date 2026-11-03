import { timingSafeEqual } from 'node:crypto';
import { sha256 } from '@signet/core';
import { PolicyError } from './errors';
import { DEFAULT_GROUP_ROLES } from './rbac';

function requiredSetting(name: string): string {
  const value = process.env[name];
  if (!value) throw new PolicyError('AUTH_CONFIG', `${name} must be configured in .env for local administrator authentication`, 503);
  return value;
}

/** The local console has one administrator; external identity providers supply any additional users. */
export function localAdminProfile(): { id: string; name: string; groups: string[] } {
  const id = requiredSetting('SIGNET_ADMIN_ID');
  return {
    id, name: id,
    groups: Object.entries(DEFAULT_GROUP_ROLES).filter(([, role]) => role !== 'automation').map(([group]) => group),
  };
}

export function verifyLocalAdminCredentials(username: string, password: string): void {
  const admin = localAdminProfile();
  const expected = requiredSetting('SIGNET_ADMIN_PASSWORD');
  const matchesId = timingSafeEqual(Buffer.from(sha256(username)), Buffer.from(sha256(admin.id)));
  const matchesPassword = timingSafeEqual(Buffer.from(sha256(password)), Buffer.from(sha256(expected)));
  if (!matchesId || !matchesPassword) throw new PolicyError('AUTH', 'invalid administrator ID or password', 401);
}
