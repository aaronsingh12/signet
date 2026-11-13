import { db } from './db';
import { requestJson } from './external-http';
import { revealForGateway } from './secrets';
import { tenant } from './tenant';

// The tenant's own approved cloud model, called from the control plane for offline Tier 2 work (DA 2):
// the attack-lab safety judge and DET-GROUND. Returns null when no model is configured or it fails.
export async function askTenantModel(messages: { role: 'system' | 'user'; content: string }[], maxTokens = 512): Promise<{ text: string; model: string } | null> {
  try {
    const entry = tenant.settings.catalogue.find((m) => !m.upstream) ?? tenant.settings.catalogue[0];
    const base = entry?.upstream?.base_url ?? process.env.SIGNET_LLM_BASE_URL;
    if (!entry || !base) return null;
    const secret = entry.upstream ? entry.upstream.secret_id : ((await db.prepare("SELECT id FROM secret WHERE tenant_id = ? AND kind = 'llm_provider' ORDER BY created_at LIMIT 1").get(tenant.id)) as { id: string } | undefined)?.id;
    const key = secret ? (await revealForGateway(secret)).value : process.env.SIGNET_LLM_API_KEY;
    const r = await requestJson({ url: new URL(`${base.replace(/\/+$/, '')}/chat/completions`), method: 'POST', timeout: 60_000, headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) }, body: JSON.stringify({
      model: entry.model, temperature: 0, max_tokens: maxTokens, stream: false, messages,
    }) }) as { choices?: { message?: { content?: string } }[] };
    const text = r?.choices?.[0]?.message?.content;
    return typeof text === 'string' ? { text, model: entry.model } : null;
  } catch {
    return null;
  }
}
