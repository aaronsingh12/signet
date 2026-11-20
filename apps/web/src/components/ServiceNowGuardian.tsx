import { Link } from 'react-router-dom';
import { useEffect } from 'react';
import { useApi } from '../lib/api';
import { CopyCode } from './CopyCode';
import { ErrorNote } from './ui';

interface GuardianSetup {
  endpoint: string; request_transformer: string; response_transformer: string;
  reviews_24h: number; flagged_24h: number; unavailable_24h: number; last_review_at: string | null; blocking_verified: boolean;
  blocked_24h: number; recent_blocks: { event_id: string; execution_id: string; at: string; categories: string[]; signet_request_id: string | null }[];
  failed_24h: number; last_error: { at: string; code: string; detail: string | null } | null;
  recent_reviews: { at: string; request_id: string | null; decision: string | null; status: string | null; categories: string[]; error_code: string | null }[];
}

/** Keeps native-content reviews visibly separate from governed MCP execution and confirmed blocking. */
export function ServiceNowGuardian({ agentId }: { agentId: string }) {
  const { data, error, loading, reload } = useApi<GuardianSetup>('/agents/' + encodeURIComponent(agentId) + '/servicenow-guardian');
  useEffect(() => {
    const timer = window.setInterval(() => void reload(), 30_000);
    return () => window.clearInterval(timer);
  }, [reload]);
  return <section className="mt-4 space-y-3 rounded-lg border border-line p-4" aria-labelledby={`guardian-heading-${agentId}`}>
    <h3 id={`guardian-heading-${agentId}`} className="font-semibold">ServiceNow chat guardrails</h3>
    <p className="text-sm text-ink-2">MCP protects routed tool calls. Native prompts and responses need ServiceNow Guardian configured to submit content here and block flagged results.</p>
    <ErrorNote error={error} />
    {loading && <p role="status">Loading Guardian setup…</p>}
    {data && <>
      <p className="text-sm">Last 24 hours: {data.reviews_24h} reviews, {data.flagged_24h} blocked by Signet, {data.unavailable_24h} of them because a check could not run. {data.blocking_verified ? 'ServiceNow carrying out blocks is evidenced by the synced events below; this does not prove every interaction is reviewed.' : 'No ServiceNow block events are evidenced in this period yet; Signet decided, but ServiceNow carrying it out is not yet confirmed.'}</p>
      <p className="text-sm" data-testid={`servicenow-native-block-count-${agentId}`}>Confirmed in ServiceNow: {data.blocked_24h} block(s) in the last 24 hours, {data.recent_blocks.filter(block => block.signet_request_id).length} of them linked to the Signet decision behind them. A block with no Signet request ID was ServiceNow's own decision.</p>
      {data.recent_blocks.length > 0 && <div className="overflow-x-auto"><table className="w-full text-sm" data-testid={`servicenow-native-blocks-${agentId}`}><caption className="text-left font-medium">Blocks ServiceNow carried out</caption><thead><tr><th className="th">Time</th><th className="th">Decided by</th><th className="th">Signet request ID</th><th className="th">Execution ID</th><th className="th">Native log ID</th><th className="th">Categories</th></tr></thead><tbody>{data.recent_blocks.map(block => <tr key={block.event_id}><td className="td">{new Date(block.at).toLocaleString()}</td><td className="td">{block.signet_request_id ? 'Signet' : 'ServiceNow'}</td><td className="td font-mono">{block.signet_request_id ?? '-'}</td><td className="td font-mono">{block.execution_id}</td><td className="td font-mono">{block.event_id}</td><td className="td">{block.categories.join(', ')}</td></tr>)}</tbody></table></div>}
      {data.last_error && <p role="alert" className="text-sm text-bad">{data.failed_24h} failed requests. Last failure at {new Date(data.last_error.at).toLocaleString()}: {data.last_error.code}. {data.last_error.detail}</p>}
      {data.last_review_at && <p className="text-xs text-ink-3">Last review: {new Date(data.last_review_at).toLocaleString()}</p>}
      <button type="button" data-testid={`servicenow-guardian-refresh-${agentId}`} className="btn-ghost" onClick={() => void reload()}>Refresh reviews</button>
      <div className="overflow-x-auto" data-testid={`servicenow-guardian-reviews-${agentId}`}>
        <table className="w-full text-sm"><caption className="text-left font-medium">Latest submitted checks (last 24 hours, up to 20). Match request IDs with ServiceNow logs to verify the native action.</caption>
          <thead><tr><th className="th">Time</th><th className="th">Verdict</th><th className="th">Categories / error</th><th className="th">Request ID</th></tr></thead>
          <tbody>{data.recent_reviews.map((review, index) => <tr key={review.request_id ?? `${review.at}-${index}`}><td className="td">{new Date(review.at).toLocaleString()}</td><td className="td">{review.error_code && review.error_code !== 'blocked_by_signet' ? 'Failed' : review.status === 'unavailable' ? 'Unavailable · flagged' : review.decision === 'flagged' ? 'Blocked by Signet' : review.decision}</td><td className="td">{review.error_code && review.error_code !== 'blocked_by_signet' ? review.error_code : review.categories.join(', ')}</td><td className="td font-mono">{review.request_id ?? 'Not recorded'}</td></tr>)}</tbody>
        </table>
        {data.recent_reviews.length === 0 && <p className="mt-2 text-ink-3">No submitted checks in the last 24 hours.</p>}
      </div>
      <ol className="list-decimal space-y-2 pl-5 text-sm">
        <li>In ServiceNow, create a separate HTTP Connection &amp; Credential Alias for this endpoint. Use OAuth 2.0 Client Credentials with this agent's Signet credentials from <Link className="text-royal" to={`/agents/${agentId}?tab=connection`}>Gateway setup</Link>. Keep your existing MCP connection.</li>
        <li>Open sys_generative_ai_custom_guardian_transformer_list.do and create an active custom guardian with ECMAScript 2021, Guardian Setting All, and the new alias.</li>
        <li>Paste the request and response transformers below. Select this custom provider in Guardian settings for the intended AI features and configure Block, not Log only.</li>
        <li>Test a benign request, a credential request and an unavailable endpoint. Confirm ServiceNow blocks flagged/failed checks before claiming enforcement.</li>
      </ol>
      <CopyCode testId={`servicenow-guardian-endpoint-${agentId}`} text={data.endpoint} />
      <details><summary className="cursor-pointer text-sm font-medium">Request transformer</summary><CopyCode testId={`servicenow-guardian-request-${agentId}`} text={data.request_transformer} /></details>
      <details><summary className="cursor-pointer text-sm font-medium">Response transformer</summary><CopyCode testId={`servicenow-guardian-response-${agentId}`} text={data.response_transformer} /></details>
      <p className="text-xs text-ink-3">Checks run fastest first: secrets, credential requests and this agent's seal data rules; then the safety judge and the prompt-attack judge together, with the prompt-injection and jailbreak detectors scoring beside them. Detected values are masked before any model sees the content; hashes and verdict metadata are logged, not the text. Shared provider credentials attribute all submitted reviews to this credential identity, so scope the provider deliberately.</p>
      <a className="text-sm text-royal" href="https://www.servicenow.com/docs/r/zurich/intelligent-experiences/configuring-byog.html" target="_blank" rel="noreferrer">ServiceNow BYOG setup documentation</a>
    </>}
  </section>;
}
