import { useState } from 'react';
import { api, useApi } from '../lib/api';
import { Card, ErrorNote } from '../components/ui';

interface Consent { agent_name: string; client_id: string; redirect_uri: string; environment: string; scope: string }

/** Explicit consent for a server-validated request bound to the current human session. */
export function OAuthConsent() {
  const request = new URLSearchParams(window.location.search).get('request');
  const path = request ? '/identity/authorization/' + encodeURIComponent(request) : null;
  const { data, error, loading } = useApi<Consent>(path);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Error | null>(null);
  const decide = async (endpoint: string): Promise<void> => {
    setBusy(true); setFailure(null);
    try {
      const result = await api<{ redirect_to: string }>(endpoint, { method: 'POST' });
      if (typeof result.redirect_to !== 'string' || !data || new URL(result.redirect_to).origin !== new URL(data.redirect_uri).origin) throw new Error('Authorization returned an invalid callback URL');
      window.location.assign(result.redirect_to);
    } catch (reason) {
      setFailure(reason instanceof Error ? reason : new Error('Authorization could not be completed; restart from the external platform'));
      setBusy(false);
    }
  };
  return <main className="mx-auto max-w-xl p-6">
    <Card title="Authorize external platform">
      {!request && <p role="alert">Authorization request is missing. Start the connection from your external platform.</p>}
      {loading && <p role="status">Loading authorization request…</p>}
      <ErrorNote error={error ?? failure} />
      {data && !error && <>
        <p className="text-sm">Allow this platform to call Signet as <strong>{data.agent_name}</strong>?</p>
        <dl className="my-4 space-y-2 break-all text-sm">
          <dt className="font-medium">Client ID</dt><dd>{data.client_id}</dd>
          <dt className="font-medium">Callback URL</dt><dd>{data.redirect_uri}</dd>
          <dt className="font-medium">Environment</dt><dd>{data.environment}</dd>
          <dt className="font-medium">Scope</dt><dd>{data.scope}</dd>
        </dl>
        <p className="mb-4 text-sm text-ink-2">Access stays limited to this agent's current approved seal. The platform receives a refresh token to renew access until expiry or revocation.</p>
        <div className="flex gap-3">
          <button type="button" data-testid="oauth-consent-deny" className="btn-ghost" disabled={busy || !path} onClick={() => void decide(path + '/deny')}>Deny</button>
          <button type="button" data-testid="oauth-consent-approve" className="btn-primary" disabled={busy || !path} onClick={() => void decide(path + '/approve')}>{busy ? 'Continuing…' : 'Allow access'}</button>
        </div>
      </>}
    </Card>
  </main>;
}
