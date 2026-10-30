import { useCallback, useEffect, useState } from 'react';

// Client for the public control API (/api/v1). The console holds no tokens: the HttpOnly session
// cookie set at sign-in authenticates every call. Errors arrive as RFC 9457 problem details.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly rule: string,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T = any>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const r = await fetch(`/api/v1${path}`, {
    method: init?.method ?? 'GET',
    headers: init?.body !== undefined || (init?.method && init.method !== 'GET') ? { 'content-type': 'application/json', 'idempotency-key': crypto.randomUUID() } : {},
    body: init?.body !== undefined ? JSON.stringify(init.body) : init?.method && init.method !== 'GET' ? '{}' : undefined,
    credentials: 'same-origin',
  });
  const text = await r.text();
  const json = text ? JSON.parse(text) : {};
  if (!r.ok) {
    if (r.status === 401 && !location.pathname.startsWith('/login')) location.assign(`/login?return_to=${encodeURIComponent(location.pathname + location.search)}`);
    throw new ApiError(r.status, json.rule ?? 'ERROR', json.detail ?? json.message ?? `request failed (${r.status})`);
  }
  return json as T;
}

export function useApi<T = any>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(false);
  const load = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    try {
      setData(await api<T>(path));
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setLoading(false);
    }
  }, [path, ...deps]);
  useEffect(() => {
    void load();
  }, [load]);
  return { data, error, loading, reload: load, setData };
}

// Server-sent events from the control plane (Live Traffic), with reconnect.
export function useLive<T>(onEvent: (e: T) => void) {
  useEffect(() => {
    let es: EventSource | null = null;
    let closed = false;
    const open = () => {
      es = new EventSource('/api/v1/live');
      es.addEventListener('record', (m) => onEvent(JSON.parse((m as MessageEvent).data) as T));
      es.onerror = () => {
        es?.close();
        if (!closed) setTimeout(open, 2000);
      };
    };
    open();
    return () => {
      closed = true;
      es?.close();
    };
  }, []);
}
