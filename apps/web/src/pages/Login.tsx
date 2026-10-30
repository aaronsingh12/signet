import { Gauge, Infinity as InfinityIcon, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { Logo } from '../components/Logo';

// Sign-in (Console UI & UX p.1). Signet stores no passwords: the tenant IdP handles sign-in and MFA.
export function Login() {
  const params = new URLSearchParams(location.search);
  const [email, setEmail] = useState('');
  const go = () => {
    const q = new URLSearchParams({ return_to: params.get('return_to') ?? '/' });
    if (email) q.set('login_hint', email);
    location.assign(`/api/v1/auth/login?${q}`);
  };
  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <div className="hidden flex-col justify-between bg-shell p-10 text-slate-300 lg:flex">
        <div className="flex items-center gap-2.5">
          <Logo />
          <div>
            <div className="font-semibold text-white">Signet</div>
            <div className="text-[11px]">by TechSnitch</div>
          </div>
        </div>
        <div className="max-w-md">
          <h1 className="text-4xl font-semibold leading-tight text-white">Nothing acts without the seal.</h1>
          <p className="mt-4 text-[15px] leading-relaxed">Independent control for every AI agent: enforced before it acts, logged in a ledger no one can quietly edit, and provable to any auditor.</p>
          <ul className="mt-8 space-y-4 text-sm">
            <li className="flex gap-3">
              <Gauge className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <span>
                <b className="text-white">Kill any agent in under one second.</b> Every gateway node acknowledges, and the console shows the count.
              </span>
            </li>
            <li className="flex gap-3">
              <InfinityIcon className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <span>
                <b className="text-white">Evidence that verifies offline.</b> Hash-chained ledger, signed daily roots, open verifier.
              </span>
            </li>
            <li className="flex gap-3">
              <ShieldCheck className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <span>
                <b className="text-white">One cloud LLM, no keys in agents.</b> Agents hold workload tokens; the gateway holds every credential.
              </span>
            </li>
          </ul>
        </div>
        <div className="text-xs">Deployment: dev · single binary profile · v0.1 (Phase 1)</div>
      </div>
      <div className="flex items-center justify-center bg-canvas p-8">
        <div className="w-full max-w-sm">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-3">Workspace</div>
          <h2 className="mt-1 text-2xl font-semibold">Sign in to Northwind Financial</h2>
          <p className="mt-2 text-sm text-ink-2">Your organisation's identity provider handles sign-in and MFA. Signet never stores your password.</p>
          <label className="label mt-6">Work email</label>
          <input className="input" type="email" placeholder="name@northwind.example" value={email} onChange={(e) => setEmail(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && go()} />
          <button className="btn-primary mt-3 w-full py-2" onClick={go}>
            Continue with SSO →
          </button>
          <p className="mt-2 text-xs text-ink-3">Routes you to the tenant identity provider (Keycloak in this dev install).</p>
          <div className="mt-6 rounded-md border border-line bg-white p-3 text-xs text-ink-2">
            Dev accounts: <span className="mono">jonas.weber</span>, <span className="mono">ananya.rao</span>, <span className="mono">priya.menon</span>, <span className="mono">arjun.mehta</span>… password <span className="mono">Signet!2026</span>
          </div>
        </div>
      </div>
    </div>
  );
}
