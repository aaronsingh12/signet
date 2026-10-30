import * as state from './state';

// Group commit to the ledger writer: records from concurrent requests travel in one batch and are
// stored in one transaction. Each request still waits for its own record before it answers the
// agent (RB-INV-15); batching only shares the cost of the write.

interface Entry {
  kind: 'transaction' | 'enforcement';
  agent_id: string | null;
  cert_id: string | null;
  data: Record<string, unknown>;
}

interface Pending {
  entry: Entry;
  resolve: (r: { record_id: string }) => void;
  reject: (e: unknown) => void;
}

const MAX_BATCH = 200;
let queue: Pending[] = [];
let timer: NodeJS.Immediate | null = null;
let inFlight = false;

export function appendRecord(entry: Entry): Promise<{ record_id: string }> {
  return new Promise((resolve, reject) => {
    queue.push({ entry, resolve, reject });
    schedule();
  });
}

// setImmediate, not setTimeout: Windows timers fire at ~15.6 ms granularity, which would add that
// much to every request. Records that arrive while a batch is in flight form the next batch.
function schedule() {
  if (timer || inFlight) return;
  timer = setImmediate(flush);
}

async function flush() {
  timer = null;
  if (!queue.length) return;
  inFlight = true;
  const batch = queue.slice(0, MAX_BATCH);
  queue = queue.slice(MAX_BATCH);
  try {
    const { records } = await state.internal<{ records: { record_id: string }[] }>('/internal/ledger', { method: 'POST', body: JSON.stringify({ records: batch.map((b) => b.entry) }) });
    batch.forEach((b, i) => b.resolve(records[i]!));
  } catch (e) {
    for (const b of batch) b.reject(e);
  } finally {
    inFlight = false;
    if (queue.length) schedule();
  }
}
