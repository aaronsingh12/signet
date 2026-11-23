import Ajv, { type JSONSchemaType } from 'ajv';
import { randomUUID } from 'node:crypto';
import { RULEBOOK_AREAS, RULEBOOK_RULES, type CustomRulebook, type CustomRulebookInput, type RuleEdit, type RulebookRule } from '@signet/core/rulebook';
import { db, nowIso, tx } from './db';
import { invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

const schema: JSONSchemaType<CustomRulebookInput> = {
  type: 'object', required: ['name', 'rules'],
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 200, pattern: '\\S' },
    rules: {
      type: 'array', minItems: 1, maxItems: 500,
      items: {
        type: 'object', required: ['id', 'area', 'text', 'note'],
        properties: {
          id: { type: 'string', minLength: 1, maxLength: 100, pattern: '\\S' },
          area: { type: 'string', minLength: 1, maxLength: 200, pattern: '\\S' },
          text: { type: 'string', minLength: 1, maxLength: 4000, pattern: '\\S' },
          note: { type: 'string', maxLength: 2000 },
        },
      },
    },
  },
};
const validate = new Ajv({ allErrors: true }).compile(schema);
const editSchema: JSONSchemaType<RuleEdit> = {
  type: 'object', required: ['area', 'text', 'note'],
  properties: {
    area: { type: 'string', minLength: 1, maxLength: 200, pattern: '\\S' },
    text: { type: 'string', minLength: 1, maxLength: 4000, pattern: '\\S' },
    note: { type: 'string', maxLength: 2000 },
  },
};
const validateEdit = new Ajv({ allErrors: true }).compile(editSchema);

type DefaultRuleEdit = { rule_id: string; area: string; text: string; note: string };

/** Tenant edits change the reference catalogue, never the compiled safety policy. */
export async function defaultRules(): Promise<RulebookRule[]> {
  const edits = await db.prepare('SELECT rule_id, area, text, note FROM default_rule_edit WHERE tenant_id = ?').all(tenant.id) as DefaultRuleEdit[];
  return RULEBOOK_RULES.map(rule => {
    const edit = edits.find(item => item.rule_id === rule.id);
    return edit ? { ...rule, area: edit.area, text: edit.text, note: edit.note } : { ...rule };
  });
}

export async function updateRule(bookId: string, ruleId: string, input: RuleEdit, actor: Principal): Promise<RuleEdit> {
  if (!validateEdit(input)) throw invalid(`Rule update failed validation: ${JSON.stringify(validateEdit.errors)}`);
  const edit: RuleEdit = { area: input.area.trim(), text: input.text.trim(), note: input.note.trim() };
  await tx(async () => {
    await db.lock();
    if (bookId === 'default') {
      if (!RULEBOOK_RULES.some(rule => rule.id === ruleId)) throw notFound(`Default rule ${ruleId}`);
      if (!RULEBOOK_AREAS.some(area => area.id === edit.area)) throw invalid(`Unknown default rule area: ${edit.area}`);
      await db.prepare('INSERT INTO default_rule_edit (tenant_id, rule_id, area, text, note, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, rule_id) DO UPDATE SET area = excluded.area, text = excluded.text, note = excluded.note, updated_at = excluded.updated_at, updated_by = excluded.updated_by').run(tenant.id, ruleId, edit.area, edit.text, edit.note, nowIso(), actor.id);
    } else {
      const books = await listRulebooks();
      const book = books.find(item => item.id === bookId);
      if (!book) throw notFound(`Rulebook ${bookId}`);
      if (!book.rules.some(rule => rule.id === ruleId)) throw notFound(`Rule ${ruleId} in rulebook ${bookId}`);
      const rules = book.rules.map(rule => rule.id === ruleId ? { id: rule.id, ...edit } : rule);
      await db.prepare('UPDATE custom_rulebook SET rules = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(rules), bookId, tenant.id);
    }
    await ledger.append({ kind: 'admin', data: { event: 'rulebook.rule_updated', rulebook_id: bookId, rule_id: ruleId, actor: actor.id, ...edit } });
  });
  return edit;
}

type StoredRulebook = { id: string; name: string; rules: string; created_at: string; created_by: string };

/** Imported rulebooks are reference material; uploading never changes runtime policy. */
export async function listRulebooks(): Promise<CustomRulebook[]> {
  const rows = await db.prepare('SELECT id, name, rules, created_at, created_by FROM custom_rulebook WHERE tenant_id = ? ORDER BY created_at DESC').all(tenant.id) as StoredRulebook[];
  return rows.map(row => {
    const parsed: CustomRulebookInput = { name: row.name, rules: JSON.parse(row.rules) };
    if (!validate(parsed)) throw new Error(`Stored rulebook ${row.id} is invalid: ${JSON.stringify(validate.errors)}`);
    return { ...parsed, id: row.id, created_at: row.created_at, created_by: row.created_by };
  });
}

export async function importRulebook(input: CustomRulebookInput, actor: Principal): Promise<CustomRulebook> {
  if (!validate(input)) throw invalid(`Rulebook upload failed validation: ${JSON.stringify(validate.errors)}`);
  const rules = input.rules.map(rule => ({ id: rule.id.trim(), area: rule.area.trim(), text: rule.text.trim(), note: rule.note.trim() }));
  const ids = rules.map(rule => rule.id.toLowerCase());
  const duplicate = ids.find((id, index) => ids.indexOf(id) !== index);
  if (duplicate) throw invalid(`Rule ID ${duplicate} appears more than once; use unique IDs within a rulebook`);
  const book: CustomRulebook = { id: `rb_${randomUUID()}`, name: input.name.trim(), rules, created_at: nowIso(), created_by: actor.id };
  await tx(async () => {
    await db.prepare('INSERT INTO custom_rulebook (id, tenant_id, name, rules, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)').run(book.id, tenant.id, book.name, JSON.stringify(book.rules), book.created_at, book.created_by);
    await ledger.append({ kind: 'admin', data: { event: 'rulebook.imported', rulebook_id: book.id, name: book.name, rules: rules.length, actor: actor.id } });
  });
  return book;
}
