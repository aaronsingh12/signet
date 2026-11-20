import { ExternalLink, Plug, Rocket } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Card, PageHeader } from '../components/ui';
import { ServiceNowConnection } from '../components/ServiceNowConnection';
import { CopilotConnection } from '../components/CopilotConnection';
import { ExternalConnections } from '../components/ExternalConnections';

export function Plugins() {
  return (
    <>
      <PageHeader title="Connections" subtitle="Connect your deployment platforms and services to bring AI agents into Signet." />
      <div className="space-y-4">
        <ServiceNowConnection />
        <CopilotConnection />
        <ExternalConnections agentId={null} />
        <Card>
          <div className="flex items-start gap-3">
            <div className="rounded-md bg-royal-50 p-2 text-royal" aria-hidden="true"><Plug size={18} /></div>
            <div>
              <h2 className="text-base font-semibold">More integrations</h2>
              <p className="mt-1 text-sm text-ink-2">Additional providers will appear here as they become available. No existing onboarding flow is replaced.</p>
            </div>
          </div>
        </Card>
      </div>
      <Card className="mt-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold">Manual onboarding</h2>
            <p className="mt-1 text-sm text-ink-2">Create and govern an agent directly in Signet, as before.</p>
          </div>
          <Link className="btn-primary inline-flex items-center gap-2" to="/agents/new">
            <Rocket size={15} /> Propose agent <ExternalLink size={14} />
          </Link>
        </div>
      </Card>
    </>
  );
}
