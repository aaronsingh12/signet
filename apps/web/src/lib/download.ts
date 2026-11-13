/** Download credentials directly from component memory; do not persist them in browser storage. */
export function downloadJson(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url; link.download = filename;
  link.click(); URL.revokeObjectURL(url);
}
