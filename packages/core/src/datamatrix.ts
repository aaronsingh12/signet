import type { CatalogueModel, CompiledAction, CompiledPolicy, DataTag } from './types';

// Data-class matrix (Rulebook v0.2). Every prompt goes to the cloud LLM, which is always treated as
// outside the tenant boundary (D-19). A seal can only tighten these defaults.

export type DataAction = 'allow' | 'log_only' | 'tokenise' | 'block' | 'require_approval';

export interface TagDecision {
  action: DataAction;
  exfiltration: boolean; // Restricted tag to a destination the seal does not allow (RB-KILL-02)
  rule: string;
}

const RESTRICTED = new Set<DataTag>(['secrets', 'payment_card', 'special_category', 'legal_privileged']);

// Prompt column.
export function promptDecision(tag: DataTag, policy: Pick<CompiledPolicy, 'prompt_tags' | 'forbidden_tags'>, model: CatalogueModel): TagDecision {
  const allowed = policy.prompt_tags.includes(tag);
  if (tag === 'secrets') return { action: 'block', exfiltration: true, rule: 'RB-INV-16' };
  if (policy.forbidden_tags.includes(tag)) return { action: 'block', exfiltration: RESTRICTED.has(tag), rule: RESTRICTED.has(tag) ? 'RB-KILL-02' : 'RB-DATA-matrix' };
  switch (tag) {
    case 'payment_card':
    case 'special_category':
      return allowed ? { action: 'tokenise', exfiltration: false, rule: 'RB-DATA-matrix' } : { action: 'block', exfiltration: true, rule: 'RB-KILL-02' };
    case 'legal_privileged':
      return { action: 'block', exfiltration: !allowed, rule: allowed ? 'RB-DATA-matrix' : 'RB-KILL-02' };
    case 'financial_account':
    case 'personal':
      // In clear only when RB-DATA-01/-02 are met; the provider terms record is not verified yet.
      return { action: 'tokenise', exfiltration: false, rule: 'RB-DATA-01' };
    case 'source_code':
      return { action: model.code_approved ? 'allow' : 'log_only', exfiltration: false, rule: 'RB-DATA-matrix' };
    case 'confidential_doc':
      return { action: allowed ? 'allow' : 'block', exfiltration: false, rule: 'RB-DATA-matrix' };
  }
}

// Tool-arguments column: tools receive only the tags in their data scope.
export function toolArgDecision(tag: DataTag, action: CompiledAction | undefined, policy: Pick<CompiledPolicy, 'forbidden_tags'>): TagDecision {
  const scoped = action?.data_scopes.includes(tag) ?? false;
  if (tag === 'secrets') return { action: 'block', exfiltration: true, rule: 'RB-INV-16' }; // the gateway injects real credentials itself
  if (policy.forbidden_tags.includes(tag) && !scoped) return { action: 'block', exfiltration: RESTRICTED.has(tag), rule: RESTRICTED.has(tag) ? 'RB-KILL-02' : 'RB-DATA-matrix' };
  switch (tag) {
    case 'payment_card':
    case 'special_category':
      return scoped ? { action: 'allow', exfiltration: false, rule: 'RB-DATA-matrix' } : { action: 'block', exfiltration: true, rule: 'RB-KILL-02' };
    case 'legal_privileged':
      return { action: 'require_approval', exfiltration: false, rule: 'RB-DATA-matrix' };
    case 'financial_account':
    case 'personal':
    case 'confidential_doc':
      return scoped ? { action: 'allow', exfiltration: false, rule: 'RB-DATA-matrix' } : { action: 'block', exfiltration: false, rule: 'RB-DATA-matrix' };
    case 'source_code':
      return { action: 'allow', exfiltration: false, rule: 'RB-DATA-matrix' };
  }
}
