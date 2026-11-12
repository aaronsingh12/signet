export const SCAN_CHECKS = ['passed', 'blocked', 'not_run', 'not_recorded'] as const;
export const SCAN_RESULTS = ['completed', 'blocked', 'review', 'failed'] as const;
export type ScanCheck = typeof SCAN_CHECKS[number];
export interface ScanEntry {
  record_id: string;
  scanned_at: string;
  result: typeof SCAN_RESULTS[number];
  input_check: ScanCheck;
  output_check: ScanCheck;
}
export interface ScanHistory { items: ScanEntry[]; next_cursor: string | null }

/** Validate metadata-only scan responses; chat content is never part of this contract. */
export function parseScanHistory(value: ScanHistory): ScanHistory {
  if (!value || !Array.isArray(value.items) || !(value.next_cursor === null || typeof value.next_cursor === 'string')) throw new TypeError('Scan history requires items and a pagination cursor');
  const items = value.items.map((item): ScanEntry => {
    if (typeof item?.record_id !== 'string' || !Number.isFinite(Date.parse(item.scanned_at))) throw new TypeError('Scan history requires a reference and valid scan date');
    if (!SCAN_RESULTS.includes(item.result)) throw new TypeError('Scan history contains an invalid result');
    for (const check of [item.input_check, item.output_check]) if (!SCAN_CHECKS.includes(check)) throw new TypeError('Scan history contains an invalid safety check');
    return { record_id: item.record_id, scanned_at: item.scanned_at, result: item.result, input_check: item.input_check, output_check: item.output_check };
  });
  return { items, next_cursor: value.next_cursor };
}
