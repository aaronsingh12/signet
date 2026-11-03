import { newId } from '@signet/core';
import { db, nowIso } from './db';
import type { Principal } from './rbac';

// In-console notifications (BP 7.3 channels). Email, Teams and Slack deliver the same items once a
// sending account is configured; the console is the channel of record.

export async function notify(recipient: string, kind: string, title: string, link?: string) {
  (await db.prepare('INSERT INTO notification (id, recipient, kind, title, link, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(newId('evt').replace('evt_', 'ntf_'), recipient, kind, title, link ?? null, nowIso()));
}

export const notifyRoles = async (roles: string[], kind: string, title: string, link?: string): Promise<void> => {
  for (const role of roles) await notify(`role:${role}`, kind, title, link);
};

const recipientsOf = (p: Principal) => [p.id, ...p.roles.map((r) => `role:${r}`)];

export async function listFor(p: Principal, limit = 30) {
  const r = recipientsOf(p);
  return (await db.prepare(`SELECT * FROM notification WHERE recipient IN (${r.map(() => '?').join(',')}) ORDER BY created_at DESC LIMIT ?`).all(...r, limit));
}

export async function unreadCount(p: Principal) {
  const r = recipientsOf(p);
  return ((await db.prepare(`SELECT COUNT(*) AS n FROM notification WHERE read_at IS NULL AND recipient IN (${r.map(() => '?').join(',')})`).get(...r)) as { n: number }).n;
}

export async function markRead(p: Principal) {
  const r = recipientsOf(p);
  (await db.prepare(`UPDATE notification SET read_at = ? WHERE read_at IS NULL AND recipient IN (${r.map(() => '?').join(',')})`).run(nowIso(), ...r));
}
