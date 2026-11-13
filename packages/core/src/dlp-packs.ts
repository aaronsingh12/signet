import type { DataTag } from './types';

// DLP country packs (BP 5.3): national identifiers and other structured personal data, each validated
// by its official check digit where one exists. Numbers that look like any other number (9 digits, for
// example) only count when a keyword is close by ("SIN", "passport" ...), so ordinary numbers are not
// flagged. Packs are switched on with SIGNET_DLP_PACKS (comma list); default: every pack except health.
//
// Tags: national IDs, passports, dates of birth and IP addresses are "personal"; SWIFT/BIC is
// "financial_account"; the health pack is "special_category" (restricted), so it is off by default.

export interface PackRecogniser {
  name: string;
  tag: DataTag;
  re: RegExp;
  check?: (match: string) => boolean;
  context?: RegExp; // must appear within 40 characters before the match
}

const digits = (s: string) => s.replace(/\D/g, '');

export function luhnOk(s: string): boolean {
  const d = digits(s);
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return d.length > 0 && sum % 10 === 0;
}

// Verhoeff (India Aadhaar).
const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
export function verhoeffOk(s: string): boolean {
  let c = 0;
  const d = digits(s).split('').reverse().map(Number);
  for (let i = 0; i < d.length; i++) c = VD[c]![VP[i % 8]![d[i]!]!]!;
  return c === 0;
}

const weighted = (d: string, w: number[]) => w.reduce((s, x, i) => s + x * Number(d[i]), 0);

export function nricOk(s: string): boolean { // Singapore NRIC / FIN (S, T, F, G and M series)
  const u = s.toUpperCase();
  const p = u[0]!;
  const sum = weighted(u.slice(1, 8), [2, 7, 6, 5, 4, 3, 2]) + (p === 'T' || p === 'G' ? 4 : p === 'M' ? 3 : 0);
  if (p === 'M') return 'KLJNPQRTUWX'[10 - (sum % 11)] === u[8];
  const table = p === 'S' || p === 'T' ? 'JZIHGFEDCBA' : 'XWUTRQPNMLK';
  return table[sum % 11] === u[8];
}

export function tfnOk(s: string): boolean { // Australia Tax File Number (9 digits)
  const d = digits(s);
  return d.length === 9 && weighted(d, [1, 4, 3, 7, 5, 8, 6, 9, 10]) % 11 === 0;
}

export function cpfOk(s: string): boolean { // Brazil CPF
  const d = digits(s);
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
  const dv = (n: number) => { const r = (weighted(d, Array.from({ length: n }, (_, i) => n + 1 - i)) * 10) % 11; return r === 10 ? 0 : r; };
  return dv(9) === Number(d[9]) && dv(10) === Number(d[10]);
}

export function bsnOk(s: string): boolean { // Netherlands BSN, 11-test
  const d = digits(s);
  return d.length === 9 && (weighted(d, [9, 8, 7, 6, 5, 4, 3, 2]) - Number(d[8])) % 11 === 0;
}

export function dniOk(s: string): boolean { // Spain DNI / NIE
  const u = s.toUpperCase().replace(/[\s-]/g, '');
  const n = u.replace(/^X/, '0').replace(/^Y/, '1').replace(/^Z/, '2');
  return 'TRWAGMYFPDXBNJZSQVHLCKE'[Number(n.slice(0, 8)) % 23] === n[8];
}

export function codiceFiscaleOk(s: string): boolean { // Italy
  const u = s.toUpperCase();
  const odd: Record<string, number> = { 0: 1, 1: 0, 2: 5, 3: 7, 4: 9, 5: 13, 6: 15, 7: 17, 8: 19, 9: 21, A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21, K: 2, L: 4, M: 18, N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23 };
  let sum = 0;
  for (let i = 0; i < 15; i++) {
    const ch = u[i]!;
    sum += i % 2 === 0 ? odd[ch]! : /\d/.test(ch) ? Number(ch) : ch.charCodeAt(0) - 65;
  }
  return String.fromCharCode(65 + (sum % 26)) === u[15];
}

export function nirOk(s: string): boolean { // France NIR (social security number) with its 2-digit key
  const d = digits(s);
  return d.length === 15 && 97 - Number(BigInt(d.slice(0, 13)) % 97n) === Number(d.slice(13));
}

export function myNumberOk(s: string): boolean { // Japan My Number (12 digits)
  const d = digits(s);
  if (d.length !== 12) return false;
  let sum = 0;
  for (let n = 1; n <= 11; n++) sum += Number(d[11 - n]) * (n <= 6 ? n + 1 : n - 5);
  const r = sum % 11;
  return (r <= 1 ? 0 : 11 - r) === Number(d[11]);
}

export function ipv4Ok(s: string): boolean {
  const p = s.split('.').map(Number);
  return p.length === 4 && p.every((x) => x >= 0 && x <= 255) && !(p[0] === 0) && !s.split('.').some((x) => x.length > 1 && x.startsWith('0'));
}

export function ninoOk(s: string): boolean { // UK National Insurance number prefixes that are never issued
  const u = s.toUpperCase().replace(/\s/g, '');
  return !['BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ'].includes(u.slice(0, 2)) && !/[DFIQUV]/.test(u.slice(0, 2)) && u[1] !== 'O';
}

const near = (words: string) => new RegExp(`\\b(?:${words})\\b`, 'i');

export const PACKS: Record<string, PackRecogniser[]> = {
  global: [
    { name: 'ipv4', tag: 'personal', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, check: ipv4Ok },
    { name: 'ipv6', tag: 'personal', re: /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b/gi },
    { name: 'swift_bic', tag: 'financial_account', re: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g, context: near('swift|bic|bank code|sort code') },
    { name: 'passport', tag: 'personal', re: /\b[A-Z0-9]{6,9}\b/g, context: near('passport(?: no| number| #)?'), check: (v) => /\d/.test(v) },
    { name: 'date_of_birth', tag: 'personal', re: /\b(?:\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}|(?:19|20)\d{2}-\d{2}-\d{2})\b/g, context: near('born|birth|dob|d\\.o\\.b\\.?|birthday') },
  ],
  us: [{ name: 'us_ssn', tag: 'personal', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g }],
  uk: [{ name: 'uk_nino', tag: 'personal', re: /\b[A-CEGHJ-PR-TW-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/gi, check: ninoOk }],
  in: [
    { name: 'in_aadhaar', tag: 'personal', re: /\b[2-9]\d{3} ?\d{4} ?\d{4}\b/g, check: verhoeffOk },
    { name: 'in_pan', tag: 'personal', re: /\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b/g },
  ],
  sg: [{ name: 'sg_nric', tag: 'personal', re: /\b[STFGM]\d{7}[A-Z]\b/gi, check: nricOk }],
  ca: [{ name: 'ca_sin', tag: 'personal', re: /\b\d{3}[ -]?\d{3}[ -]?\d{3}\b/g, check: luhnOk, context: near('sin|social insurance') }],
  au: [{ name: 'au_tfn', tag: 'personal', re: /\b\d{3} ?\d{3} ?\d{3}\b/g, check: tfnOk, context: near('tfn|tax file') }],
  br: [{ name: 'br_cpf', tag: 'personal', re: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, check: cpfOk }],
  eu: [
    { name: 'nl_bsn', tag: 'personal', re: /\b\d{9}\b/g, check: bsnOk, context: near('bsn|burgerservicenummer') },
    { name: 'es_dni', tag: 'personal', re: /\b[XYZ]?\d{7,8}-?[A-Z]\b/gi, check: dniOk },
    { name: 'it_codice_fiscale', tag: 'personal', re: /\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b/gi, check: codiceFiscaleOk },
    { name: 'fr_nir', tag: 'personal', re: /\b[12] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b/g, check: nirOk },
  ],
  ae: [{ name: 'ae_emirates_id', tag: 'personal', re: /\b784-?\d{4}-?\d{7}-?\d\b/g, check: luhnOk }],
  sa: [{ name: 'sa_national_id', tag: 'personal', re: /\b[12]\d{9}\b/g, check: luhnOk, context: near('national id|iqama|هوية') }],
  jp: [{ name: 'jp_my_number', tag: 'personal', re: /\b\d{4} ?\d{4} ?\d{4}\b/g, check: myNumberOk, context: near('my number|individual number|マイナンバー') }],
  // Restricted data class: switch on only where the seal lists special_category for the agent.
  health: [
    { name: 'icd10_code', tag: 'special_category', re: /\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b/g, context: near('icd|diagnos(?:is|ed)|condition') },
    { name: 'health_term', tag: 'special_category', re: /\b(?:diagnosed with|hiv(?:\+| positive)|chemotherapy|diabetes|cancer|depression|pregnan(?:t|cy)|schizophrenia|bipolar disorder)\b/gi },
  ],
};

export const DEFAULT_PACKS = Object.keys(PACKS).filter((p) => p !== 'health');

/** Packs switched on by SIGNET_DLP_PACKS ("all", "none" or a comma list); default every pack except health. */
export function enabledPacks(setting = typeof process !== 'undefined' ? process.env.SIGNET_DLP_PACKS : undefined): string[] {
  const v = setting?.trim().toLowerCase();
  if (!v) return DEFAULT_PACKS;
  if (v === 'none') return [];
  if (v === 'all') return Object.keys(PACKS);
  const list = v.split(',').map((x) => x.trim()).filter(Boolean);
  const unknown = list.filter((x) => !PACKS[x]);
  if (unknown.length) throw new Error(`SIGNET_DLP_PACKS: unknown pack(s) ${unknown.join(', ')}; available: ${Object.keys(PACKS).join(', ')}`);
  return list;
}

export const packRecognisers = (packs = enabledPacks()): PackRecogniser[] => packs.flatMap((p) => PACKS[p] ?? []);
