import { useState } from 'react';
import { api } from '../lib/api';
import { ErrorNote } from './ui';

export type Platform = 'vercel' | 'aws' | 'azure' | 'gcp' | 'copilot' | 'openai' | 'anthropic';
export interface PlatformAccount { id: string; platform: Platform; label: string; status: string; status_detail: string | null; last_scan_at: string | null }

export const PLATFORM_NAMES: Record<Platform, string> = { vercel: 'Vercel', aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', copilot: 'Copilot Studio', openai: 'OpenAI', anthropic: 'Anthropic' };
const FIELDS: Record<Platform, { key: string; label: string; secret?: boolean; area?: boolean; optional?: boolean }[]> = {
  vercel: [{ key: 'token', label: 'Access token (Account settings → Tokens)', secret: true }, { key: 'team_id', label: 'Team ID', optional: true }],
  aws: [{ key: 'access_key_id', label: 'Access key ID' }, { key: 'secret_access_key', label: 'Secret access key', secret: true }, { key: 'regions', label: 'Regions, comma-separated', optional: true }],
  azure: [{ key: 'tenant_id', label: 'Tenant ID' }, { key: 'client_id', label: 'App (client) ID' }, { key: 'client_secret', label: 'Client secret', secret: true }, { key: 'subscription_id', label: 'Subscription ID' }],
  gcp: [{ key: 'service_account_json', label: 'Service account key (JSON)', area: true }, { key: 'regions', label: 'Regions, comma-separated', optional: true }],
  copilot: [{ key: 'environment_url', label: 'Environment URL (https://<org>.crm.dynamics.com)' }, { key: 'tenant_id', label: 'Tenant ID' }, { key: 'client_id', label: 'App (client) ID' }, { key: 'client_secret', label: 'Client secret', secret: true }],
  openai: [{ key: 'admin_key', label: 'Organization admin key', secret: true }],
  anthropic: [{ key: 'admin_key', label: 'Organization admin key', secret: true }],
};
const HELP: Record<Platform, string> = {
  vercel: 'Lists projects and their environment variable names; connects a project by setting its variables and redeploying.',
  aws: 'Read access lists Bedrock agents and Lambda functions; lambda:UpdateFunctionConfiguration lets Signet connect a function.',
  azure: 'Reader lists Azure OpenAI, AI Foundry and App Service; Website Contributor lets Signet connect an App Service app.',
  gcp: 'Lists Vertex AI Agent Engine agents and Cloud Run services. Cloud Run deployment requires permission to update the service.',
  copilot: 'Lists Copilot Studio agents from the Dataverse environment (the app registration needs an application user there).',
  openai: 'Lists projects and API keys used directly against OpenAI, with their owners and usage; can delete a key.',
  anthropic: 'Lists API keys used directly against Anthropic, with usage; can set a key inactive.',
};
export function PlatformAccountForm({ onConnected, onEdit }: { onConnected: (connection: PlatformAccount) => void; onEdit: () => void }) {
  const [platform, setPlatform] = useState<Platform>('vercel');
  const [form, setForm] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const connect = async () => {
    onEdit();
    setBusy(true);
    try {
      const connection = await api<PlatformAccount>('/platforms', { method: 'POST', body: { platform, ...form } });
      if (!connection || typeof connection.id !== 'string' || !connection.id || typeof connection.label !== 'string' || connection.platform !== platform || connection.status !== 'connected') throw new TypeError('Platform connection response must contain an ID, label, the requested provider and connected status');
      setForm({});
      setFormError(null);
      onConnected(connection);
    } catch (e) {
      if (!(e instanceof Error)) throw e;
      setFormError(e);
    } finally {
      setBusy(false);
    }
  };
  const ready = FIELDS[platform].every((f) => f.optional || (form[f.key] ?? '').trim());
  return (
    <fieldset disabled={busy} onChangeCapture={onEdit}>
        <div className="mb-2 flex flex-wrap gap-2">
          {(Object.keys(PLATFORM_NAMES) as Platform[]).map((p) => (
            <button type="button" data-testid={`platform-provider-${p}`} key={p} aria-pressed={platform === p} onClick={() => { onEdit(); setPlatform(p); setForm({}); setFormError(null); }} className={`rounded-md px-3 py-1.5 text-sm ${platform === p ? 'bg-royal text-white' : 'bg-canvas text-ink-2 hover:bg-slate-200'}`}>{PLATFORM_NAMES[p]}</button>
          ))}
        </div>
        <p className="text-xs text-ink-3">{HELP[platform]} The credential goes to the Secrets Broker; gateways can never read it.</p>
        <div className="mt-2 grid gap-2 md:grid-cols-2">
          {FIELDS[platform].map((f) => f.area ? (
            <textarea data-testid={`platform-field-${f.key}`} aria-label={f.label} key={f.key} className="input mono min-h-24 text-xs md:col-span-2" placeholder={f.label} value={form[f.key] ?? ''} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
          ) : (
            <input data-testid={`platform-field-${f.key}`} aria-label={f.label} key={f.key} className="input" type={f.secret ? 'password' : 'text'} placeholder={`${f.label}${f.optional ? ' (optional)' : ''}`} value={form[f.key] ?? ''} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
          ))}
          <input className="input" placeholder="Label (optional)" value={form.label ?? ''} onChange={(e) => setForm({ ...form, label: e.target.value })} />
        </div>
        <button type="button" data-testid="platform-connect" className="btn-primary mt-2" disabled={busy || !ready} onClick={() => void connect()}>{busy ? 'Checking…' : `Connect ${PLATFORM_NAMES[platform]}`}</button>
        <div className="mt-2"><ErrorNote error={formError} /></div>
    </fieldset>
  );
}
