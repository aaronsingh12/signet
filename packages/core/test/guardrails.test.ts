import { strict as assert } from 'node:assert';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  BASELINE_DAYS, GUARDRAILS, GUARDRAIL_GROUPS, GUARDRAIL_PARAMS, MIN_BASELINE_DAYS, MIN_BASELINE_RECORDS, PIPELINE_STEPS,
  RULEBOOK_AREAS, RULEBOOK_RULES, guardrailsForRule, rulebookRule,
} from '../src/index';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');

// Every source file in the product: all apps, all packages and the Rego policy. Tests, fixtures and the
// catalogue files themselves are skipped.
function sources(): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (['node_modules', 'test', 'dist', 'e2e'].includes(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|tsx|mts|mjs|rego)$/.test(name)) out.push(relative(ROOT, p).replace(/\\/g, '/'));
    }
  };
  for (const top of ['apps', 'packages', 'policy']) walk(join(ROOT, top));
  return out.filter((f) => !/packages\/core\/src\/(guardrails|rulebook|guardrail-params)\.ts$/.test(f) && !/\/src\/.*\/(test|fixtures)\//.test(f));
}

// Rule IDs that guard the console and its integrations, not agents, so they are not guardrails.
// Adding an ID here needs a reason.
const NOT_GUARDRAILS: Record<string, string> = {
  'BP-9.1': 'control library: reviewing framework-to-control links',
  'BP-9.3': 'control library: licensed frameworks must be imported',
  'BP-9.4': 'control library: spreadsheet import rules',
  'BP-10': 'ServiceNow connector: self-test before use',
  'BP-10.9': 'ServiceNow connector: retrying dead letters',
  'BP-14.1': 'console: type the agent handle to confirm a kill',
};
const CITED = /["'`]((?:RB|BP|DA|DET|SN-GUARD)-[A-Za-z0-9.-]+|cert\.hitl)["'`]/g;

test('every rule ID cited anywhere in the code is in the guardrail catalogue', () => {
  const catalogued = new Set(GUARDRAILS.flatMap((g) => [...g.rule_ids, ...(g.rulebook ?? [])]));
  const missing = new Map<string, Set<string>>();
  const files = sources();
  assert.ok(files.some((f) => f.startsWith('apps/gateway/src/')) && files.some((f) => f.startsWith('apps/control/src/')) && files.includes('policy/signet.rego'), 'source scan found no code');
  for (const file of files) {
    for (const [, raw] of readFileSync(join(ROOT, file), 'utf8').matchAll(CITED)) {
      const id = raw!.replace(/\.(tool|output|challenger)$/, '');
      if (catalogued.has(id) || NOT_GUARDRAILS[id]) continue;
      if (!missing.has(id)) missing.set(id, new Set());
      missing.get(id)!.add(file);
    }
  }
  const list = [...missing].map(([id, f]) => `${id} (${[...f].join(', ')})`);
  assert.deepEqual(list, [], `add these rule IDs to packages/core/src/guardrails.ts, or to NOT_GUARDRAILS with a reason:\n${list.join('\n')}`);
  for (const id of Object.keys(NOT_GUARDRAILS)) assert.ok(!catalogued.has(id), `${id} is both a guardrail and in NOT_GUARDRAILS`);
});

// Words like T1, L0, rule IDs and HTTP status codes are fine; any other number in a description must
// come from GUARDRAIL_PARAMS, so the page cannot show a value the code no longer uses.
const ALLOWED_DIGITS = [/\b[TL][0-4]\b/g, /\b[A-Z]+(?:-[A-Z0-9.]+)+\b/g, /\b(?:202|429|503)\b/g, /\blevel \d\b/g, /\bmod-97\b/g, /"refunds over 5,000[^"]*"/g];
const strip = (text: string) => ALLOWED_DIGITS.reduce((t, re) => t.replace(re, ''), text);

test('guardrail descriptions quote the enforced numbers instead of typing them', () => {
  const src = readFileSync(join(ROOT, 'packages/core/src/guardrails.ts'), 'utf8');
  const typed: string[] = [];
  for (const m of src.matchAll(/^\s+what: (['`])(.*)\1,\r?$/gm)) {
    const text = strip(m[2]!.replace(/\$\{[^}]*\}/g, ''));
    if (/\d/.test(text)) typed.push(m[2]!.slice(0, 90));
  }
  assert.deepEqual(typed, [], `use GUARDRAIL_PARAMS for the numbers in:\n${typed.join('\n')}`);
});

test('Rulebook coverage notes only quote numbers the code uses', () => {
  const known = new Set<string>();
  const collect = (v: unknown) => {
    if (typeof v === 'number') { known.add(String(v)); known.add(v.toLocaleString('en-US')); }
    else if (v && typeof v === 'object') Object.values(v).forEach(collect);
  };
  collect(GUARDRAIL_PARAMS);
  [BASELINE_DAYS, MIN_BASELINE_DAYS, MIN_BASELINE_RECORDS].forEach(collect);
  for (const r of RULEBOOK_RULES) {
    for (const n of strip(r.note ?? '').match(/\d[\d,.]*/g) ?? []) {
      assert.ok(known.has(n.replace(/[.,]$/, '')), `${r.id}: the note quotes ${n}, which is not a value in GUARDRAIL_PARAMS`);
    }
  }
});

test('policy/signet.rego uses the same dual-control amount as the TypeScript evaluator', () => {
  const rego = readFileSync(join(ROOT, 'policy/signet.rego'), 'utf8');
  const amounts = [...rego.matchAll(/money > (\d+)/g)].map((m) => Number(m[1]));
  assert.deepEqual(amounts, [GUARDRAIL_PARAMS.dual_control_usd], 'update policy/signet.rego to match GUARDRAIL_PARAMS.dual_control_usd');
});

test('catalogue entries are complete and point at real code', () => {
  const groups = new Set(GUARDRAIL_GROUPS.map((g) => g.id));
  const keys = new Set<string>();
  for (const g of GUARDRAILS) {
    assert.ok(!keys.has(g.key), `duplicate key ${g.key}`);
    keys.add(g.key);
    assert.ok(groups.has(g.group), `${g.key}: unknown group ${g.group}`);
    assert.ok(g.name && g.what && g.source, `${g.key}: name, what and source are required`);
    if (g.step !== undefined) assert.ok(PIPELINE_STEPS.some((s) => s.n === g.step), `${g.key}: step ${g.step} is not a pipeline step`);
    assert.ok(g.code.length > 0, `${g.key}: name the enforcing code`);
    for (const file of g.code) assert.ok(existsSync(join(ROOT, file)), `${g.key}: ${file} does not exist`);
  }
  for (const grp of GUARDRAIL_GROUPS) assert.ok(GUARDRAILS.some((g) => g.group === grp.id), `group ${grp.id} is empty`);
});

test('the pipeline has the 14 BP 5.2 steps in order', () => {
  assert.deepEqual(PIPELINE_STEPS.map((s) => s.n), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  assert.equal(PIPELINE_STEPS[13]!.name, 'log and score');
});

test('ledger rule IDs resolve to their guardrail, including detector sub-results', () => {
  assert.deepEqual(guardrailsForRule('RB-KILL-02').map((g) => g.key), ['kill-exfiltration']);
  assert.deepEqual(guardrailsForRule('DET-INJ.tool').map((g) => g.key), ['det-inj']);
  assert.deepEqual(guardrailsForRule('NOPE-1'), []);
});

test('the Rulebook and the guardrail catalogue agree', () => {
  const ids = RULEBOOK_RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate Rulebook rule');
  const areas = new Set(RULEBOOK_AREAS.map((a) => a.id));
  for (const r of RULEBOOK_RULES) assert.ok(areas.has(r.area), `${r.id}: unknown area ${r.area}`);
  for (const r of RULEBOOK_RULES) if (r.coverage === 'partial' || r.coverage === 'not_built') assert.ok(r.note, `${r.id}: say what is missing`);
  const linked = new Map<string, string[]>();
  for (const g of GUARDRAILS) for (const id of [...g.rule_ids, ...(g.rulebook ?? [])]) linked.set(id, [...(linked.get(id) ?? []), g.key]);
  // A guardrail never claims a Rulebook rule that is not built.
  for (const [id, keys] of linked) {
    const rule = rulebookRule(id);
    if (rule) assert.notEqual(rule.coverage, 'not_built', `${id} is not built but guardrail(s) ${keys.join(', ')} cite it`);
  }
  // Every built (or partly built) Rulebook rule appears on the Guardrails view.
  const unlinked = RULEBOOK_RULES.filter((r) => (r.coverage === 'enforced' || r.coverage === 'partial') && !linked.has(r.id)).map((r) => r.id);
  assert.deepEqual(unlinked, [], `link these Rulebook rules to a guardrail: ${unlinked.join(', ')}`);
});
