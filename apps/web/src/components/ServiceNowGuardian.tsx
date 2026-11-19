import { Link } from 'react-router-dom';
import { useApi } from '../lib/api';
import { CopyCode } from './CopyCode';
import { ErrorNote } from './ui';

interface GuardianSetup {
  endpoint: string; request_transformer: string; response_transformer: string;
  reviews_24h: number; flagged_24h: number; unavailable_24h: number; last_review_at: string | null; blocking_verified: false;
  failed_24h: number; last_error: { at: string; code: string; detail: string | null } | null;
}

/** Keeps native-content reviews visibly separate from governed MCP execution and confirmed blocking. */
export function ServiceNowGuardian({ agentId }: { agentId: string }) {
  const { data, error, loading, reload } = useApi<GuardianSetup>('/agents/' + encodeURIComponent(agentId) + '/servicenow-guardian');
  return <section className="mt-4 space-y-3 rounded-lg border border-line p-4" aria-labelledby={`guardian-heading-${agentId}`}>
    <h3 id={`guardian-heading-${agentId}`} className="font-semibold">ServiceNow chat guardrails</h3>
    <p className="text-sm text-ink-2">MCP protects routed tool calls. Native prompts and responses need ServiceNow Guardian configured to submit content here and block flagged results.</p>
    <ErrorNote error={error} />
    {loading && <p role="status">Loading Guardian setup…</p>}
    {data && <>
      <p className="text-sm">Last 24 hours: {data.reviews_24h} reviews, {data.flagged_24h} flagged, {data.unavailable_24h} unavailable. ServiceNow blocking requires a live test; submitted verdicts do not prove every interaction is intercepted.</p>
      {data.last_error && <p role="alert" className="text-sm text-bad">{data.failed_24h} failed requests. Last failure at {new Date(data.last_error.at).toLocaleString()}: {data.last_error.code}. {data.last_error.detail}</p>}
      {data.last_review_at && <p className="text-xs text-ink-3">Last review: {new Date(data.last_review_at).toLocaleString()}</p>}
      <button type="button" data-testid={`servicenow-guardian-refresh-${agentId}`} className="btn-ghost" onClick={() => void reload()}>Refresh reviews</button>
      <ol className="list-decimal space-y-2 pl-5 text-sm">
        <li>In ServiceNow, create a separate HTTP Connection &amp; Credential Alias for this endpoint. Use OAuth 2.0 Client Credentials with this agent's Signet credentials from <Link className="text-royal" to={`/agents/${agentId}?tab=connection`}>Gateway setup</Link>. Keep your existing MCP connection.</li>
        <li>Open sys_generative_ai_custom_guardian_transformer_list.do and create an active custom guardian with ECMAScript 2021, Guardian Setting All, and the new alias.</li>
        <li>Paste the request and response transformers below. Select this custom provider in Guardian settings for the intended AI features and configure Block, not Log only.</li>
        <li>Test a benign request, a credential request and an unavailable endpoint. Confirm ServiceNow blocks flagged/failed checks before claiming enforcement.</li>
      </ol>
      <CopyCode testId={`servicenow-guardian-endpoint-${agentId}`} text={data.endpoint} />
      <details><summary className="cursor-pointer text-sm font-medium">Request transformer</summary><CopyCode testId={`servicenow-guardian-request-${agentId}`} text={data.request_transformer} /></details>
      <details><summary className="cursor-pointer text-sm font-medium">Response transformer</summary><CopyCode testId={`servicenow-guardian-response-${agentId}`} text={data.response_transformer} /></details>
      <p className="text-xs text-ink-3">Review text is scanned for secrets before classification. Detected values are masked before the existing safety model reviews other content; hashes and verdict metadata are logged. Shared provider credentials attribute all submitted reviews to this credential identity, so scope the provider deliberately.</p>
      <a className="text-sm text-royal" href="https://www.servicenow.com/docs/r/zurich/intelligent-experiences/configuring-byog.html" target="_blank" rel="noreferrer">ServiceNow BYOG setup documentation</a>
    </>}
  </section>;
}
