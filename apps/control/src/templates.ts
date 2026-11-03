import type { Autonomy, DataTag, Impact, Tier } from '@signet/core';
import { tenant } from './tenant';

// Seal templates (BP 1B.6 Day-One Onboarding; Rulebook seal-template defaults). A template pre-fills
// the intake and the manifest draft; the owner binds suggested actions to registered tool aliases at
// Assess. Values are starting points, narrowed per agent.

export interface Template {
  id: string;
  name: string;
  tier_hint: Tier;
  autonomy: Autonomy;
  users_affected: ('internal' | 'customers' | 'public')[];
  decisions_about_individuals: boolean;
  data_touched: DataTag[];
  suggested_actions: { name: string; impact: Impact; note?: string }[];
  prompt_tags: DataTag[];
  forbidden_tags: DataTag[];
  limits: { rpm: number; tokens_per_day: number; usd_per_day: number; tool_calls_per_session?: number };
  hitl_notes: string;
}

export const TEMPLATES: Template[] = [
  {
    id: 'TPL-CS', name: 'Customer service assistant', tier_hint: 'T3', autonomy: 'L2', users_affected: ['customers'], decisions_about_individuals: false,
    data_touched: ['personal'],
    suggested_actions: [{ name: 'search_kb', impact: 'read' }, { name: 'lookup_order', impact: 'read' }, { name: 'create_ticket', impact: 'write' }, { name: 'issue_refund', impact: 'privileged', note: 'HITL over USD 100' }, { name: 'send_customer_email', impact: 'privileged' }],
    prompt_tags: ['personal'], forbidden_tags: ['payment_card', 'special_category'],
    limits: { rpm: 300, tokens_per_day: 2_000_000, usd_per_day: 200, tool_calls_per_session: 20 },
    hitl_notes: 'Refund over USD 100; any account change; any outbound email not from an approved template',
  },
  {
    id: 'TPL-ITOPS', name: 'IT operations agent', tier_hint: 'T2', autonomy: 'L2', users_affected: ['internal'], decisions_about_individuals: false,
    data_touched: ['source_code', 'confidential_doc'],
    suggested_actions: [{ name: 'search_logs', impact: 'read' }, { name: 'update_ticket', impact: 'write' }, { name: 'restart_service', impact: 'privileged' }, { name: 'change_prod_config', impact: 'critical' }],
    prompt_tags: ['source_code'], forbidden_tags: ['secrets'],
    limits: { rpm: 120, tokens_per_day: 1_000_000, usd_per_day: 150 },
    hitl_notes: 'All privileged actions in prod; all critical actions always; change-gated deploy',
  },
  {
    id: 'TPL-TRIAGE', name: 'Claims or case triage agent', tier_hint: 'T2', autonomy: 'L2', users_affected: ['customers'], decisions_about_individuals: true,
    data_touched: ['personal', 'special_category'],
    suggested_actions: [{ name: 'get_case', impact: 'read' }, { name: 'add_note', impact: 'write' }, { name: 'recommend_outcome', impact: 'privileged' }, { name: 'approve_payout', impact: 'critical' }],
    prompt_tags: ['personal'], forbidden_tags: ['payment_card'],
    limits: { rpm: 60, tokens_per_day: 1_000_000, usd_per_day: 150 },
    hitl_notes: 'Every adverse recommendation reviewed; payout always; bias suite mandatory',
  },
  {
    id: 'TPL-CODE', name: 'Coding assistant', tier_hint: 'T3', autonomy: 'L2', users_affected: ['internal'], decisions_about_individuals: false,
    data_touched: ['source_code'],
    suggested_actions: [{ name: 'read_repo', impact: 'read' }, { name: 'open_pull_request', impact: 'write' }],
    prompt_tags: ['source_code'], forbidden_tags: ['secrets', 'payment_card'],
    limits: { rpm: 120, tokens_per_day: 2_000_000, usd_per_day: 100 },
    hitl_notes: 'Merge to protected branches and deploys are not allowed',
  },
  {
    id: 'TPL-DATA', name: 'Data analysis agent', tier_hint: 'T3', autonomy: 'L2', users_affected: ['internal'], decisions_about_individuals: false,
    data_touched: ['personal', 'confidential_doc'],
    suggested_actions: [{ name: 'run_query', impact: 'read', note: 'max 10,000 rows' }, { name: 'create_report', impact: 'write' }, { name: 'export_dataset', impact: 'privileged' }],
    prompt_tags: [], forbidden_tags: ['payment_card', 'special_category'],
    limits: { rpm: 60, tokens_per_day: 1_000_000, usd_per_day: 100 },
    hitl_notes: 'Export; any query returning more than 100 personal rows',
  },
  {
    id: 'TPL-BACKOFFICE', name: 'Back-office automation agent', tier_hint: 'T2', autonomy: 'L3', users_affected: ['internal'], decisions_about_individuals: false,
    data_touched: ['financial_account', 'personal'],
    suggested_actions: [{ name: 'read_erp', impact: 'read' }, { name: 'create_invoice', impact: 'write' }, { name: 'initiate_payment', impact: 'privileged', note: 'HITL over USD 1,000' }, { name: 'change_vendor_bank_details', impact: 'critical' }],
    prompt_tags: ['financial_account'], forbidden_tags: ['payment_card'],
    limits: { rpm: 120, tokens_per_day: 1_000_000, usd_per_day: 150 },
    hitl_notes: 'Payment over USD 1,000; dual approval over USD 10,000; every bank-detail change',
  },
];

export const getTemplate = (id: string | undefined) => TEMPLATES.find((t) => t.id === id) ?? null;

// Manifest draft from a template: the model is the tenant's cloud LLM; tools are bound at Assess.
export function manifestFrom(t: Template | null) {
  return {
    models: [{ model: tenant.settings.catalogue[0]!.model, region: tenant.settings.catalogue[0]!.region, max_tokens: 1000 }],
    tools: [],
    data_classes: { prompt: t?.prompt_tags ?? [], forbidden: t?.forbidden_tags ?? ['payment_card', 'special_category'] },
    hitl: [],
    limits: t?.limits ?? { rpm: 60, tokens_per_day: 500_000, usd_per_day: 50, tool_calls_per_session: 40 },
    environments: ['dev'],
    tags: [],
  };
}
