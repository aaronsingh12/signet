export function ago(ts: string | number | null | undefined): string {
  if (!ts) return '—';
  const ms = Date.now() - (typeof ts === 'number' ? ts : Date.parse(ts));
  if (ms < 0) return 'just now';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s} s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

export const date = (ts: string | null | undefined) => (ts ? new Date(ts).toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' }) : '—');
export const time = (ts: string | null | undefined) => (ts ? new Date(ts).toISOString().slice(11, 23) : '—');
export const short = (s: string | null | undefined, n = 10) => (!s ? '—' : s.length <= n + 4 ? s : `${s.slice(0, n)}…`);
export const hash = (s: string | null | undefined) => (!s ? '—' : `${s.slice(0, 4)}…${s.slice(-4)}`);
export const num = (n: number | null | undefined) => (n === null || n === undefined ? '—' : n.toLocaleString());

export function daysLeft(ts: string | null | undefined) {
  if (!ts) return null;
  return Math.ceil((Date.parse(ts) - Date.now()) / 86_400_000);
}

export function dlpSummary(d: Record<string, number> | null | undefined): string {
  if (!d) return '—';
  const parts = Object.entries(d)
    .filter(([k]) => !k.endsWith(':allow'))
    .map(([k, v]) => {
      const [, tag, action] = k.split(':');
      return `${tag} ×${v} ${action === 'tokenise' ? 'tokenised' : action === 'block' ? 'blocked' : action === 'redact' ? 'redacted' : action === 'mask' ? 'masked' : action}`;
    });
  return parts.length ? parts.join(', ') : '—';
}
