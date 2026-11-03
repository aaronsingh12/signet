import { writeFileSync } from 'node:fs';
import { strict as assert } from 'node:assert';
import { join } from 'node:path';
import { DATA_DIR, automationToken, devUserToken, env, type CertificateBody } from '@signet/core';
import type { AgentRow } from '../../control/src/registry';

const agents = [
  { key: 'appointment-agent', name: 'Appointment Agent', purpose: 'Hospital scheduling, availability and appointment management.' },
  { key: 'records-agent', name: 'Patient Records Agent', purpose: 'Authorized patient profiles, medical history, visit summaries and prescriptions.' },
  { key: 'lab-agent', name: 'Lab Report Agent', purpose: 'Authorized diagnostic reports and clinician review requests.' },
  { key: 'care-agent', name: 'Care Coordinator Agent', purpose: 'Hospital FAQs, support tickets and multi-agent coordination.' },
] as const;

interface AgentDetail { agent: AgentRow; certificate: CertificateBody | null }
interface Deployment { agent_id: string; deployment_credential: string; expires_at: string }

function parseAgent(text: string): AgentRow {
  const agent = JSON.parse(text) as AgentRow;
  assert(agent && typeof agent === 'object', 'Control API must return an agent object');
  for (const field of ['id', 'handle', 'owner', 'sponsor'] as const) assert(typeof agent[field] === 'string' && agent[field].length, `Agent ${field} must be a nonempty string`);
  assert(['T1', 'T2', 'T3', 'T4'].includes(agent.tier), 'Agent tier must be T1-T4');
  assert(['L0', 'L1', 'L2', 'L3', 'L4'].includes(agent.autonomy_level), 'Agent autonomy must be L0-L4');
  return agent;
}

function parseDetail(text: string): AgentDetail {
  const detail = JSON.parse(text) as AgentDetail;
  assert(detail && typeof detail === 'object' && Object.hasOwn(detail, 'certificate'), 'Control API must return an agent and certificate');
  const agent = parseAgent(JSON.stringify(detail.agent));
  if (detail.certificate !== null) {
    const cert = detail.certificate;
    assert(cert && cert.agent_id === agent.id, 'Certificate must belong to the returned agent');
    for (const field of ['models', 'tools', 'hitl', 'environments', 'tags'] as const) assert(Array.isArray(cert[field]), `Certificate ${field} must be an array`);
    assert(cert.models.length && cert.models.every((model) => typeof model.model === 'string' && typeof model.region === 'string'), 'Certificate model grants must include model and region');
    assert(cert.environments.every((environment) => typeof environment === 'string' && environment.length), 'Certificate environments must be nonempty strings');
    assert(cert.tags.every((tag) => typeof tag === 'string'), 'Certificate tags must be strings');
    assert(cert.data_classes && Array.isArray(cert.data_classes.prompt) && Array.isArray(cert.data_classes.forbidden), 'Certificate data classes must include prompt and forbidden arrays');
    assert(cert.limits && cert.limits.rpm > 0 && cert.limits.tokens_per_day > 0 && cert.limits.usd_per_day >= 0, 'Certificate limits must include positive RPM, tokens and a nonnegative budget');
    assert(typeof cert.ai_disclosure === 'boolean', 'Certificate must specify AI disclosure');
    assert(cert.detector_unavailability === undefined || ['hold', 'audit'].includes(cert.detector_unavailability), 'Certificate detector policy must be hold or audit');
  }
  return { agent, certificate: detail.certificate };
}

function parseAgents(text: string): AgentRow[] {
  const response = JSON.parse(text) as { items: AgentRow[] };
  assert(response && Array.isArray(response.items), 'Control API agent search must return items[]');
  return response.items.map((agent) => parseAgent(JSON.stringify(agent)));
}

function parseDeployment(text: string): Deployment {
  const deployment = JSON.parse(text) as Deployment;
  assert(deployment && typeof deployment.agent_id === 'string' && typeof deployment.deployment_credential === 'string' && deployment.deployment_credential.startsWith('sdc_') && typeof deployment.expires_at === 'string' && Number.isFinite(Date.parse(deployment.expires_at)), 'Control API deployment must include agent_id, an sdc_ credential and a valid expires_at');
  return deployment;
}

async function api(token: string, method: string, path: string, body: object | undefined): Promise<string> {
  const url = `${env('SIGNET_CONTROL_URL', 'http://localhost:4100')}/api/v1${path}`;
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url, {
        method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000),
      });
      const text = await response.text();
      if (!response.ok) throw new Error(`${method} ${url} failed (${response.status}): ${text}`);
      return text;
    } catch (error) {
      // Mutations must not be repeated after an ambiguous network failure.
      if (attempt === 3 || method !== 'GET') throw error;
      console.warn('Hospital provisioning read failed; retrying', { url, attempt, error });
    }
  }
}

/** Prepare independent hospital identities; newly proposed agents complete lifecycle approval before credentials are issued. */
async function provision(): Promise<void> {
  const templateRef = process.argv[2];
  if (!templateRef) throw new Error('Usage: npm run hospital:provision -- <existing-hospital-agent-handle>');
  const adminId = process.env.SIGNET_ADMIN_ID;
  const adminPassword = process.env.SIGNET_ADMIN_PASSWORD;
  if (!adminId || !adminPassword) throw new Error('SIGNET_ADMIN_ID and SIGNET_ADMIN_PASSWORD must be configured for local hospital provisioning');
  const admin = await devUserToken(adminId, adminPassword);
  const automation = await automationToken();
  const template = parseDetail(await api(admin, 'GET', `/agents/${encodeURIComponent(templateRef)}`, undefined));
  if (!template.certificate) throw new Error(`Hospital template ${templateRef} has no active seal`);
  const cert = template.certificate;
  if (cert.environments.length !== 1) throw new Error('Hospital template must cover exactly one deployment environment');
  const deployments: Record<string, Deployment> = {};
  const pending: string[] = [];
  for (const definition of agents) {
    const handle = `hospital-${definition.key}`;
    const existing = parseAgents(await api(admin, 'GET', `/agents?q=${handle}`, undefined));
    const found = existing.find((agent) => agent.handle === handle);
    const agent = found ?? parseAgent(await api(automation, 'POST', '/agents', {
      handle, name: definition.name, purpose: definition.purpose, owner: template.agent.owner,
      sponsor: template.agent.sponsor, tier: template.agent.tier, autonomy_level: template.agent.autonomy_level,
    }));
    if (agent.owner !== template.agent.owner || agent.tier !== template.agent.tier || agent.autonomy_level !== template.agent.autonomy_level) {
      throw new Error(`Existing agent ${handle} does not match the hospital template owner, tier or autonomy; review it before provisioning`);
    }
    const detail = parseDetail(await api(admin, 'GET', `/agents/${agent.id}`, undefined));
    if (!detail.certificate) { pending.push(handle); continue; }
    const deployment = parseDeployment(await api(admin, 'POST', `/agents/${agent.id}/deployment-credentials`, { environment: cert.environments[0] }));
    assert.equal(deployment.agent_id, agent.id, 'Deployment credential must belong to the requested agent');
    deployments[definition.key] = deployment;
    // Save after each agent so a partial failure never loses issued credentials.
    writeFileSync(join(DATA_DIR, 'hospital-agents.json'), JSON.stringify(deployments, null, 2), { mode: 0o600 });
    console.log(`${definition.name}: ${agent.id}`);
  }
  if (pending.length) throw new Error(`Complete the lifecycle approvals in Signet for ${pending.join(', ')}, then rerun hospital:provision. Credentials for already-approved agents were saved to data/hospital-agents.json.`);
  console.log('Agent credentials saved to data/hospital-agents.json. Configure the four matching hospital backend credentials before redeploying.');
}

await provision();
