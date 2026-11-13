// Spreadsheet reading for the framework importer (BP 9.4). Runs in the browser and in Node 18+ with no
// extra libraries: CSV is parsed by hand (RFC 4180 quoting), XLSX is a ZIP of XML files read with
// DecompressionStream. Every worksheet is returned so the user can pick one. Formulas give their cached value.

export type SheetRows = string[][];

/** Parse CSV text: comma or semicolon separated, double-quoted fields, "" for a quote, CRLF or LF lines. */
export function parseCsv(text: string): SheetRows {
  const src = text.replace(/^﻿/, '');
  const firstLine = src.slice(0, src.search(/\r?\n|$/));
  const sep = (firstLine.match(/;/g)?.length ?? 0) > (firstLine.match(/,/g)?.length ?? 0) ? ';' : ',';
  const rows: SheetRows = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (quoted) {
      if (ch === '"' && src[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"' && field === '') quoted = true;
    else if (ch === sep) { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && src[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += ch;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim() !== ''));
}

// --- XLSX ---------------------------------------------------------------------------------------

interface ZipEntry { name: string; method: number; offset: number; compressed: number }

function zipEntries(buf: Uint8Array): ZipEntry[] {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('not an XLSX file (no ZIP directory found)');
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const out: ZipEntry[] = [];
  const dec = new TextDecoder();
  for (let n = 0; n < count; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) throw new Error('damaged XLSX file');
    const method = dv.getUint16(p + 10, true);
    const compressed = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const offset = dv.getUint32(p + 42, true);
    out.push({ name: dec.decode(buf.subarray(p + 46, p + 46 + nameLen)), method, offset, compressed });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

async function readEntry(buf: Uint8Array, e: ZipEntry): Promise<string> {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const start = e.offset + 30 + dv.getUint16(e.offset + 26, true) + dv.getUint16(e.offset + 28, true);
  const data = buf.subarray(start, start + e.compressed);
  if (e.method === 0) return new TextDecoder().decode(data);
  if (e.method !== 8) throw new Error(`unsupported compression in ${e.name}`);
  const stream = new Blob([data as unknown as ArrayBuffer]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new TextDecoder().decode(await new Response(stream).arrayBuffer());
}

const unescape = (s: string) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d))).replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&amp;/g, '&');
const texts = (xml: string) => [...xml.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)].map((m) => unescape(m[1]!)).join('');
const colIndex = (ref: string) => [...ref.replace(/\d+$/, '')].reduce((n, ch) => n * 26 + ch.charCodeAt(0) - 64, 0) - 1;

/** Every worksheet of an XLSX file, in tab order, as rows of text. */
export async function parseXlsx(input: ArrayBuffer | Uint8Array): Promise<{ name: string; rows: SheetRows }[]> {
  const buf = input instanceof Uint8Array ? input : new Uint8Array(input);
  const entries = zipEntries(buf);
  const find = (name: string) => entries.find((e) => e.name === name);
  const shared = find('xl/sharedStrings.xml');
  const strings = shared ? [...(await readEntry(buf, shared)).matchAll(/<si>([\s\S]*?)<\/si>/g)].map((m) => texts(m[1]!)) : [];
  // Every sheet in workbook (tab) order, resolved through the workbook relationships.
  const out: { name: string; rows: SheetRows }[] = [];
  const wb = find('xl/workbook.xml');
  const rels = find('xl/_rels/workbook.xml.rels');
  if (wb && rels) {
    const relXml = await readEntry(buf, rels);
    for (const sm of (await readEntry(buf, wb)).matchAll(/<sheet\b([^>]*)\/?>/g)) {
      const name = unescape(sm[1]!.match(/\bname="([^"]*)"/)?.[1] ?? 'Sheet');
      const rid = sm[1]!.match(/\br:id="([^"]+)"/)?.[1];
      const target = rid && relXml.match(new RegExp(`<Relationship\\b[^>]*Id="${rid}"[^>]*Target="([^"]+)"`))?.[1];
      const entry = target && find(target.startsWith('/') ? target.slice(1) : `xl/${target.replace(/^\.\//, '')}`);
      if (entry) out.push({ name, rows: sheetRows(await readEntry(buf, entry), strings) });
    }
  }
  if (!out.length) {
    for (const e of entries.filter((x) => /^xl\/worksheets\/sheet\d+\.xml$/.test(x.name))) out.push({ name: e.name.replace(/^.*\/|\.xml$/g, ''), rows: sheetRows(await readEntry(buf, e), strings) });
  }
  if (!out.length) throw new Error('the XLSX file has no worksheet');
  return out;
}

function sheetRows(xml: string, strings: string[]): SheetRows {
  const rows: SheetRows = [];
  for (const rm of xml.matchAll(/<row\b[^>]*>([\s\S]*?)<\/row>/g)) {
    const row: string[] = [];
    for (const cm of rm[1]!.matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const attrs = cm[1]!;
      const body = cm[2] ?? '';
      const ref = attrs.match(/\br="([A-Z]+\d+)"/)?.[1];
      const type = attrs.match(/\bt="([^"]+)"/)?.[1];
      const v = body.match(/<v>([\s\S]*?)<\/v>/)?.[1];
      const value = type === 's' ? strings[Number(v)] ?? '' : type === 'inlineStr' ? texts(body) : v !== undefined ? unescape(v) : '';
      const idx = ref ? colIndex(ref) : row.length;
      while (row.length < idx) row.push('');
      row[idx] = value;
    }
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c.trim() !== ''));
}
