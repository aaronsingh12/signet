import { newId } from '@signet/core';
import { db, nowIso } from './db';
import type { Principal } from './rbac';

// In-console notifications (BP 7.3 channels). Email, Teams and Slack deliver the same items once a
// sending account is configured; the console is the channel of record.

export function notify(recipient: string, kind: string, title: string, link?: string) {
  db.prepare('INSERT INTO notification (id, recipient, kind, title, link, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(newId('evt').replace('evt_', 'ntf_'), recipient, kind, title, link ?? null, nowIso());
}

export const notifyRoles = (roles: string[], kind: string, title: string, link?: string) => roles.forEach((r) => notify(`role:${r}`, kind, title, link));

const recipientsOf = (p: Principal) => [p.id, ...p.roles.map((r) => `role:${r}`)];

export function listFor(p: Principal, limit = 30) {
  const r = recipientsOf(p);
  return db.prepare(`SELECT * FROM notification WHERE recipient IN (${r.map(() => '?').join(',')}) ORDER BY created_at DESC LIMIT ?`).all(...r, limit);
}

export function unreadCount(p: Principal) {
  const r = recipientsOf(p);
  return (db.prepare(`SELECT COUNT(*) AS n FROM notification WHERE read_at IS NULL AND recipient IN (${r.map(() => '?').join(',')})`).get(...r) as { n: number }).n;
}

export function markRead(p: Principal) {
  const r = recipientsOf(p);
  db.prepare(`UPDATE notification SET read_at = ? WHERE read_at IS NULL AND recipient IN (${r.map(() => '?').join(',')})`).run(nowIso(), ...r);
}
