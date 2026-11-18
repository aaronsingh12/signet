import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { ErrorNote } from './ui';
import { api, useApi } from '../lib/api';

interface SavedSettings {
  id: string;
  gateway_url: string;
  instance_url: string;
  mcp_url: string;
  client_id: string;
  has_client_secret: boolean;
  callback_url: string;
}

interface SetupProps { onSaved: () => void; onCancel: () => void }

const emptyDraft = { gateway_url: '', instance_url: '', mcp_url: '', client_id: '', client_secret: '' };
type SettingsDraft = typeof emptyDraft;

function savedConnectionId(response: { settings: { id: string } }): string {
  if (typeof response?.settings?.id !== 'string' || !response.settings.id) throw new Error('ServiceNow settings were saved without a connection ID; open All connections to verify the saved connection');
  return response.settings.id;
}

async function createConnection(draft: SettingsDraft): Promise<string> {
  const response = await api<{ settings: { id: string } }>('/plugins/servicenow/connections', { method: 'POST', body: draft });
  return savedConnectionId(response);
}

export function ServiceNowSetup({ onSaved, onCancel }: SetupProps) {
  return <ServiceNowSettingsForm settings={null} saveSettings={createConnection} onSaved={onSaved} onCancel={onCancel} />;
}

export function EditServiceNowSetup({ connectionId, onSaved, onCancel }: SetupProps & { connectionId: string }) {
  const { data, error } = useApi<{ settings: SavedSettings }>('/plugins/servicenow/connections/' + encodeURIComponent(connectionId) + '/settings');
  if (error) return <ErrorNote error={error} />;
  if (!data) return <p role="status">Loading ServiceNow settings?</p>;
  const updateConnection = async (draft: SettingsDraft): Promise<string> => {
    const response = await api<{ settings: { id: string } }>('/plugins/servicenow/connections/' + encodeURIComponent(connectionId) + '/settings', { method: 'PUT', body: draft });
    return savedConnectionId(response);
  };
  return <ServiceNowSettingsForm key={connectionId} settings={data.settings} saveSettings={updateConnection} onSaved={onSaved} onCancel={onCancel} />;
}

function ServiceNowSettingsForm({ settings, saveSettings, onSaved, onCancel }: SetupProps & { settings: SavedSettings | null; saveSettings: (draft: SettingsDraft) => Promise<string> }) {
  const [draft, setDraft] = useState({ gateway_url: settings?.gateway_url ?? '', instance_url: settings?.instance_url ?? '',
    mcp_url: settings?.mcp_url ?? '', client_id: settings?.client_id ?? '', client_secret: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const redirectUrl = `${(draft.gateway_url.trim() || window.location.origin).replace(/\/+$/, '')}/api/v1/plugins/servicenow/callback`;
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const connectionId = await saveSettings(draft);
      setDraft({ ...emptyDraft });
      onSaved();
      window.location.assign('/api/v1/plugins/servicenow/connections/' + encodeURIComponent(connectionId) + '/connect');
    } catch (failure) {
      setError(failure instanceof Error ? failure : new Error('ServiceNow settings could not be saved'));
    } finally {
      setSaving(false);
    }
  };
  return <form data-testid="servicenow-setup-form" onSubmit={event => void save(event)} className="space-y-4">
    <p className="text-sm text-ink-2">Save your ServiceNow connection, then authorize access to discover its MCP tools. Agent activity monitoring requires an execution-data tool.</p>
    <div>
      <label className="label" htmlFor="servicenow-redirect-url">ServiceNow Redirect URL</label>
      <input id="servicenow-redirect-url" data-testid="servicenow-redirect-url" className="input" readOnly value={redirectUrl} onFocus={event => event.currentTarget.select()} aria-describedby="servicenow-redirect-help" />
      <p id="servicenow-redirect-help" className="mt-1 text-xs text-ink-3">Copy this into ServiceNow OAuth → Redirect URLs. It updates with the Public Signet URL below; before you enter one, it shows this app's address.</p>
    </div>
    <div><label className="label" htmlFor="servicenow-gateway-url">Public Signet / Gateway URL</label>
      <input id="servicenow-gateway-url" type="url" className="input" required value={draft.gateway_url} onChange={event => setDraft({ ...draft, gateway_url: event.target.value })} placeholder="https://your-signet-domain.example" />
      <p className="mt-1 text-xs text-ink-3">The public Signet address that serves both the console API and gateway.</p></div>
    <div><label className="label" htmlFor="servicenow-instance-url">ServiceNow instance URL</label>
      <input id="servicenow-instance-url" type="url" className="input" required value={draft.instance_url} onChange={event => setDraft({ ...draft, instance_url: event.target.value })} placeholder="https://your-instance.service-now.com" /></div>
    <div><label className="label" htmlFor="servicenow-mcp-url">ServiceNow MCP server URL</label>
      <input id="servicenow-mcp-url" type="url" className="input" required value={draft.mcp_url} onChange={event => setDraft({ ...draft, mcp_url: event.target.value })} /></div>
    <div><label className="label" htmlFor="servicenow-client-id">OAuth Client ID</label>
      <input id="servicenow-client-id" className="input" required maxLength={256} value={draft.client_id} onChange={event => setDraft({ ...draft, client_id: event.target.value })} /></div>
    <div><label className="label" htmlFor="servicenow-client-secret">OAuth Client Secret</label>
      <input id="servicenow-client-secret" type="password" autoComplete="new-password" className="input" required={!settings?.has_client_secret} minLength={8} maxLength={4096} value={draft.client_secret} onChange={event => setDraft({ ...draft, client_secret: event.target.value })} />
      {settings?.has_client_secret && <p className="mt-1 text-xs text-ink-3">A secret is saved. Leave this blank to keep it, or enter a replacement.</p>}</div>
    <ErrorNote error={error} />
    <div className="flex flex-wrap gap-2">
      <button type="submit" data-testid="servicenow-save-settings" className="btn-primary" disabled={saving}>{saving ? 'Saving and connecting…' : 'Save and connect'}</button>
      <Link data-testid="servicenow-all-connections" className="btn-ghost" to="/settings/systems" onClick={onCancel}>All connections</Link>
      <button type="button" className="btn-ghost" onClick={onCancel} disabled={saving}>Cancel</button>
    </div>
  </form>;
}
