import { useState, type FormEvent } from 'react';
import { ApiError, api, useApi } from '../lib/api';
import { ErrorNote } from './ui';
import { CopyCode } from './CopyCode';

/** Registers the external OAuth client's exact callback before enabling authorization-code consent. */
export function OAuthClientSettings({ clientId, controlUrl }: { clientId: string; controlUrl: string }) {
  const path = '/identity/clients/' + encodeURIComponent(clientId) + '/oauth';
  const { data, error, loading, reload } = useApi<{ redirect_uri: string }>(path);
  const [redirect, setRedirect] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [saveError, setSaveError] = useState<Error | null>(null);
  const [saved, setSaved] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setBusy(true); setSaveError(null); setSaved(false);
    try {
      await api<{ redirect_uri: string }>(path, { method: 'PUT', body: { redirect_uri: redirect ?? data?.redirect_uri ?? '' } });
      await reload(); setSaved(true);
    } catch (failure) {
      setSaveError(failure instanceof Error ? failure : new ApiError(500, 'OAUTH', 'Callback URL could not be saved'));
    } finally { setBusy(false); }
  };
  return <section className="mt-4 rounded-lg border border-line p-4" aria-labelledby="oauth-code-heading">
    <h3 id="oauth-code-heading" className="font-medium">OAuth Authorization Code</h3>
    <p className="mt-2 text-sm text-ink-2">For platforms using browser sign-in. Register the exact callback URL supplied by that platform, then use these endpoints with your saved Client ID and Secret.</p>
    <CopyCode testId="setup-oauth-endpoints" text={`Authorization URL: ${controlUrl}/api/v1/identity/authorize\nToken URL: ${controlUrl}/api/v1/identity/token\nGrant type: authorization_code\nToken authentication: client_secret_basic or client_secret_post\nPKCE: S256 required\nScope: mcp`} />
    <ErrorNote error={error ?? saveError} />
    <form className="mt-3 space-y-3" onSubmit={event => void submit(event)}>
      <label className="label" htmlFor="setup-oauth-redirect">External platform callback URL</label>
      <input id="setup-oauth-redirect" data-testid="setup-oauth-redirect" className="input" type="url" required maxLength={2048} disabled={loading || busy || !data || Boolean(error)} value={redirect ?? data?.redirect_uri ?? ''} onChange={event => { setRedirect(event.target.value); setSaved(false); }} placeholder="https://your-instance.service-now.com/oauth_redirect.do" />
      <p className="text-xs text-ink-3">Use the ServiceNow outbound provider callback, not Signet's ServiceNow inbound callback. Saving invalidates this client's pending authorizations and refresh tokens.</p>
      <button type="submit" data-testid="setup-oauth-save-redirect" className="btn-primary" disabled={loading || busy || !data || Boolean(error)}>{busy ? 'Saving…' : 'Save callback URL'}</button>
      {saved && <p role="status" className="text-sm text-ok">Callback saved. Start authorization from your external platform.</p>}
    </form>
  </section>;
}
