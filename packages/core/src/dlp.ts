import type { DataTag } from './types';

// Pattern DLP (BP 5.3): regex and checksum recognisers that run inline in well under a millisecond.
// The ML recogniser (DET-PII) is a detector and is wired separately.

export interface Finding {
  recogniser: string;
  tag: DataTag;
  start: number;
  end: number;
  value: string;
}

interface Recogniser {
  name: string;
  tag: DataTag;
  re: RegExp;
  check?: (match: string) => boolean;
}

export function luhn(digits: string): boolean {
  const d = digits.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

export function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s/g, '').toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of v) rem = (rem * 10 + Number(digit)) % 97;
  }
  return rem === 1;
}

const RECOGNISERS: Recogniser[] = [
  { name: 'private_key', tag: 'secrets', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  { name: 'aws_access_key', tag: 'secrets', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'api_key_sk', tag: 'secrets', re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g },
  { name: 'github_token', tag: 'secrets', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { name: 'slack_token', tag: 'secrets', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'jwt', tag: 'secrets', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { name: 'connection_string', tag: 'secrets', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:/@]+:[^\s@]+@[^\s]+/g },
  { name: 'password_assignment', tag: 'secrets', re: /\b(?:password|passwd|pwd)\s*[:=]\s*\S{6,}/gi },
  { name: 'payment_card', tag: 'payment_card', re: /\b\d(?:[ -]?\d){12,18}\b/g, check: luhn },
  { name: 'iban', tag: 'financial_account', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g, check: ibanValid },
  { name: 'email', tag: 'personal', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // Not preceded or followed by another digit group, so long numbers (cards, IBANs) are never read as phones.
  { name: 'phone', tag: 'personal', re: /(?<![\w+-])(?<!\d[ .-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)|\d{2,4})[ .-]?\d{3,4}[ .-]?\d{3,4}(?![ .-]?\d)/g },
];

export function scan(text: string): Finding[] {
  const found: Finding[] = [];
  for (const r of RECOGNISERS) {
    for (const m of text.matchAll(r.re)) {
      const value = m[0];
      if (r.check && !r.check(value)) continue;
      const start = m.index ?? 0;
      found.push({ recogniser: r.name, tag: r.tag, start, end: start + value.length, value });
    }
  }
  // Earlier recognisers win on overlap (secrets before cards before phone numbers).
  found.sort((a, b) => a.start - b.start);
  const out: Finding[] = [];
  for (const f of found) {
    const clash = out.find((o) => f.start < o.end && o.start < f.end);
    if (!clash) out.push(f);
    else if (RECOGNISERS.findIndex((r) => r.name === f.recogniser) < RECOGNISERS.findIndex((r) => r.name === clash.recogniser)) {
      out.splice(out.indexOf(clash), 1, f);
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

// Replace each finding with the string from fn, right to left so offsets stay valid.
export function rewrite(text: string, findings: Finding[], fn: (f: Finding) => string): string {
  let out = text;
  for (const f of [...findings].sort((a, b) => b.start - a.start)) out = out.slice(0, f.start) + fn(f) + out.slice(f.end);
  return out;
}

export const maskCard = (v: string) => `**** **** **** ${v.replace(/\D/g, '').slice(-4)}`;
