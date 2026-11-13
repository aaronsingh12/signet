import { useState } from 'react';
import { parseAgentConnectionFile, type AgentConnectionFile, type ConnectionIdentity } from '@signet/core/agent-config';
import { downloadJson } from '../lib/download';
import { CopyCode } from './CopyCode';
import { ErrorNote } from './ui';

/** Export the once-issued identity for an SDK or sidecar without requiring an environment file. */
export function AgentConfigDownload({ agentId, controlUrl, gatewayUrl, identity }: { agentId: string; controlUrl: string; gatewayUrl: string; identity: ConnectionIdentity }) {
  const [error, setError] = useState<Error | null>(null);
  const download = (): void => {
    try {
      const config: AgentConnectionFile = { version: 1, control_url: controlUrl, gateway_url: gatewayUrl.replace(/\/+$/, ''), identity, token_cache: `.signet-token-${agentId}.json` };
      downloadJson('signet-agent.json', JSON.stringify(parseAgentConnectionFile(config), null, 2));
      setError(null);
    } catch (cause) { if (!(cause instanceof Error)) throw cause; setError(cause); }
  };
  return <div className="mt-4 space-y-3 rounded-lg border border-line p-3">
    <p className="text-sm font-medium">Connect without editing .env</p>
    <p className="text-xs text-ink-3">Download this agent's connection file and place it on its server. It contains the issued credential; keep it private. Signet stores the identity and revocation state in the database.</p>
    <button type="button" data-testid="agent-config-download" className="btn-primary" onClick={download}>Download signet-agent.json</button>
    <p className="text-xs text-ink-3">For a Python agent:</p>
    <CopyCode testId="agent-config-python" text={'from signet_sdk import SignetAgent\n\nagent = SignetAgent.from_file("signet-agent.json")\nagent.connect()'} />
    <p className="text-xs text-ink-3">For a no-code app, start the sidecar with this file, then set its AI base URL to http://127.0.0.1:8300/v1 in the app's settings:</p>
    <CopyCode testId="agent-config-sidecar" text="npm run sidecar -- --config signet-agent.json" />
    <ErrorNote error={error} />
  </div>;
}
