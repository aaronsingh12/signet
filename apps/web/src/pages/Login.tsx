import { Gauge, Infinity as InfinityIcon, ShieldCheck } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Logo } from '../components/Logo';

// Sign-in (Console UI & UX p.1). Production delegates authentication to the tenant IdP.
export function Login() {
  const params = new URLSearchParams(location.search);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [config, setConfig] = useState<{ auth_mode: 'local' | 'oidc'; tenant_name: string } | null>(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  useEffect(() => {
    fetch('/api/v1/auth/config').then(async (response) => {
      if (!response.ok) throw new Error(`Authentication configuration request failed (HTTP ${response.status})`);
      const data = await response.json() as { auth_mode: string; tenant_name: string };
      if ((data.auth_mode !== 'local' && data.auth_mode !== 'oidc') || typeof data.tenant_name !== 'string') throw new Error('Invalid authentication configuration response');
      setConfig({ auth_mode: data.auth_mode, tenant_name: data.tenant_name });
    }).catch((failure: Error) => setError(failure.message));
  }, []);
  const go = async () => {
    setError('');
    if (!config) { setError('Authentication configuration has not loaded.'); return; }
    const q = new URLSearchParams({ return_to: params.get('return_to') ?? '/' });
    if (config.auth_mode === 'local') {
      setPending(true);
      try {
        const response = await fetch('/api/v1/auth/local-login', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ username: email, password, return_to: q.get('return_to') }),
        });
        const data = await response.json() as { detail?: string; redirect_to?: string };
        if (!response.ok) throw new Error(data.detail ?? `Sign-in failed (HTTP ${response.status})`);
        if (!data.redirect_to?.startsWith('/') || data.redirect_to.startsWith('//')) throw new Error('Invalid sign-in redirect response');
        location.assign(data.redirect_to);
      } catch (failure) {
        setError(failure instanceof Error ? failure.message : String(failure));
      } finally { setPending(false); }
      return;
    }
    if (email) q.set('login_hint', email);
    location.assign(`/api/v1/auth/login?${q}`);
  };
  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <div className="hidden flex-col justify-between bg-[#123b38] p-12 text-emerald-100/75 lg:flex">
        <div className="flex items-center gap-2.5">
          <Logo />
          <div>
            <div className="font-semibold text-white">Signet</div>
            <div className="text-[11px]">by TechSnitch</div>
          </div>
        </div>
        <div className="max-w-md">
          <h1 className="text-5xl font-semibold leading-tight tracking-tight text-white">Know your AI.<br />Stay in control.</h1>
          <p className="mt-5 text-[15px] leading-relaxed">One clear place to understand your AI agents, follow their activity and manage what they’re allowed to do.</p>
          <ul className="mt-8 space-y-4 text-sm">
            <li className="flex gap-3">
              <Gauge className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <span>
                <b className="text-white">A clear view of every agent.</b> See its status, requests and usage in simple charts.
              </span>
            </li>
            <li className="flex gap-3">
              <InfinityIcon className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <span>
                <b className="text-white">An activity history you can trust.</b> Review recorded actions and export verifiable evidence.
              </span>
            </li>
            <li className="flex gap-3">
              <ShieldCheck className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <span>
                <b className="text-white">Independent safety controls.</b> Each agent has its own permissions, limits and approval.
              </span>
            </li>
          </ul>
        </div>
        <div className="text-xs">Agent governance console</div>
      </div>
      <div className="flex items-center justify-center bg-canvas p-8">
        <div className="w-full max-w-sm">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-3">Workspace</div>
          <h2 className="mt-1 text-2xl font-semibold">Sign in{config ? ` to ${config.tenant_name}` : ''}</h2>
          <form onSubmit={(event) => { event.preventDefault(); void go(); }}>
            <label className="label mt-6" htmlFor="signet-login-id">{config?.auth_mode === 'local' ? 'Administrator ID' : 'Work email'}</label>
            <input id="signet-login-id" className="input" type="text" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} />
            {config?.auth_mode === 'local' && <>
              <label className="label mt-4" htmlFor="signet-login-password">Password</label>
              <input id="signet-login-password" className="input" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
            </>}
            {error && <p role="alert" className="mt-3 text-sm text-red-700">{error}</p>}
            <button id="signet-login-submit" className="btn-primary mt-3 w-full py-2" type="submit" disabled={!config || pending}>
              {pending ? 'Signing in…' : config?.auth_mode === 'local' ? 'Sign in' : 'Continue with SSO →'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
