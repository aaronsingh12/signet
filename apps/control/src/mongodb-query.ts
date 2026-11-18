import { createHash } from 'node:crypto';
import type { Expr, ExprCall, SelectStatement, SelectedColumn } from 'pgsql-ast-parser';
import { COLLECTIONS, type StoredValue } from './mongodb-schema';

export type MongoValue = StoredValue | MongoValue[] | { [key: string]: MongoValue };
export type MongoStage = { [key: string]: MongoValue };
interface Reference { path: string; columns: string[] }
interface Context {
  references: Record<string, Reference>;
  values: StoredValue[];
  ctes: Record<string, SelectStatement>;
  grouped: Record<string, string>;
}
interface CompiledExpression { value: MongoValue; stages: MongoStage[] }
export interface QueryPlan {
  collection: string | null;
  pipeline: MongoStage[];
  columns: string[];
}

const literal = (value: MongoValue): MongoValue => ({ $literal: value });
const expressionKey = (expression: Expr): string => JSON.stringify(expression);
const aggregateNames = new Set(['count', 'sum', 'avg', 'min', 'max', 'string_agg', 'array_agg']);

function reference(expression: Extract<Expr, { type: 'ref' }>, context: Context): string {
  const available = Object.entries(context.references).filter(([name]) => name !== 'excluded').map(([, source]) => source);
  const local = available.filter(source => !source.path.startsWith('$$') || source.path === '$$ROOT');
  const outer = available.filter(source => source.path.startsWith('$$') && source.path !== '$$ROOT');
  const source = expression.table ? context.references[expression.table.name]
    : [...local, ...outer].find(candidate => candidate.columns.includes(expression.name));
  if (!source) throw new TypeError(`MongoDB query references an unavailable field: ${expression.table ? expression.table.name + '.' : ''}${expression.name}`);
  return `${source.path}.${expression.name}`;
}

function combined(expressions: Expr[], context: Context): { values: MongoValue[]; stages: MongoStage[] } {
  const compiled = expressions.map(expression => compileExpression(expression, context));
  return { values: compiled.map(expression => expression.value), stages: compiled.flatMap(expression => expression.stages) };
}

function jsonExpression(expression: Expr, context: Context): CompiledExpression {
  if (expression.type === 'cast') return jsonExpression(expression.operand, context);
  if (expression.type === 'ref') {
    const path = reference(expression, context);
    const position = path.lastIndexOf('.');
    return { value: path.slice(0, position) + '.__json' + path.slice(position), stages: [] };
  }
  if (expression.type === 'string') return { value: literal(JSON.parse(expression.value) as MongoValue), stages: [] };
  return compileExpression(expression, context);
}

function subquery(expression: SelectStatement, context: Context): CompiledExpression {
  const outer = Object.entries(context.references);
  const variables = Object.fromEntries(outer.map(([name, source], index) => [name, { ...source, path: `$$outer${index}` }]));
  const plan = compileSelect(expression, context.values, context.ctes, variables);
  const field = 'subquery' + createHash('sha256').update(expressionKey(expression)).digest('hex').slice(0, 12);
  const lookup: MongoStage = { $lookup: {
    ...(plan.collection ? { from: plan.collection } : {}),
    let: Object.fromEntries(outer.map(([, source], index) => [`outer${index}`, source.path])),
    pipeline: plan.pipeline, as: field,
  } };
  const column = plan.columns[0];
  if (!column) throw new TypeError('A scalar MongoDB subquery must select a column');
  return { value: { $map: { input: '$' + field, as: 'row', in: `$$row.${column}` } }, stages: [lookup] };
}

function compileCall(expression: ExprCall, context: Context): CompiledExpression {
  const name = expression.function.name.toLowerCase();
  if (name === 'exists') {
    const query = expression.args[0];
    if (!query || !['select', 'with', 'union', 'union all'].includes(query.type)) throw new TypeError('EXISTS requires a query');
    const result = subquery(query as SelectStatement, context);
    return { value: { $gt: [{ $size: result.value }, 0] }, stages: result.stages };
  }
  if (name === 'jsonb_extract_path_text' || name === 'jsonb_extract_path') {
    const first = expression.args[0];
    if (!first) throw new TypeError(`${name} requires a document`);
    const input = jsonExpression(first, context);
    const path = expression.args.slice(1).map(argument => {
      if (argument.type !== 'string') throw new TypeError('JSON document paths must be string literals');
      return argument.value;
    });
    const value = path.reduce<MongoValue>((current, field) => ({ $getField: { field: literal(field), input: current } }), input.value);
    return { value: name.endsWith('_text') ? { $convert: { input: value, to: 'string', onNull: null } } : value, stages: input.stages };
  }
  if (name === 'jsonb_typeof') {
    const first = expression.args[0];
    if (!first) throw new TypeError('jsonb_typeof requires a document');
    const input = jsonExpression(first, context);
    const type = { $type: input.value };
    return { value: { $switch: { branches: [
      { case: { $in: [type, ['double', 'int', 'long', 'decimal']] }, then: 'number' },
      { case: { $eq: [type, 'bool'] }, then: 'boolean' },
      { case: { $eq: [type, 'missing'] }, then: null },
    ], default: type } }, stages: input.stages };
  }
  const args = combined(expression.args, context);
  const value = (operator: string): CompiledExpression => ({ value: { [operator]: args.values }, stages: args.stages });
  if (name === 'random') return { value: { $rand: {} }, stages: [] };
  if (name === 'coalesce') return value('$ifNull');
  if (name === 'greatest') return value('$max');
  if (name === 'least') return value('$min');
  if (name === 'lower') return { value: { $toLower: args.values[0]! }, stages: args.stages };
  if (name === 'upper') return { value: { $toUpper: args.values[0]! }, stages: args.stages };
  if (name === 'strpos') return { value: { $add: [{ $indexOfCP: args.values }, 1] }, stages: args.stages };
  if (name === 'length' || name === 'char_length') return { value: { $strLenCP: args.values[0]! }, stages: args.stages };
  if (name === 'abs') return { value: { $abs: args.values[0]! }, stages: args.stages };
  if (name === 'round') return value('$round');
  if (name === 'replace') return { value: { $replaceAll: { input: args.values[0]!, find: args.values[1]!, replacement: args.values[2]! } }, stages: args.stages };
  if (name === 'substr' || name === 'substring') return { value: { $substrCP: [args.values[0]!, { $subtract: [args.values[1]!, 1] }, args.values[2] ?? 2147483647] }, stages: args.stages };
  if (name === 'trim' || name === 'btrim') return { value: { $trim: { input: args.values[0]! } }, stages: args.stages };
  if (name === 'jsonb_array_length') return { value: { $size: args.values[0]! }, stages: args.stages };
  if (name === 'nullif') return { value: { $cond: [{ $eq: args.values }, null, args.values[0]!] }, stages: args.stages };
  throw new TypeError(`MongoDB query function is not supported: ${name}`);
}

function compileExpression(expression: Expr, context: Context): CompiledExpression {
  const grouped = context.grouped[expressionKey(expression)];
  if (grouped) return { value: grouped, stages: [] };
  switch (expression.type) {
    case 'null': return { value: null, stages: [] };
    case 'string': case 'integer': case 'numeric': case 'boolean': return { value: literal(expression.value), stages: [] };
    case 'parameter': {
      const index = Number(expression.name.slice(1)) - 1;
      if (index < 0 || index >= context.values.length) throw new RangeError(`Missing query parameter ${expression.name}`);
      return { value: literal(context.values[index]!), stages: [] };
    }
    case 'ref': return { value: { $ifNull: [reference(expression, context), null] }, stages: [] };
    case 'cast': {
      if ('name' in expression.to && ['json', 'jsonb'].includes(expression.to.name)) return jsonExpression(expression.operand, context);
      const result = compileExpression(expression.operand, context);
      if (!('name' in expression.to)) throw new TypeError('MongoDB query casts require a named type');
      const target = ['integer', 'int', 'bigint', 'double precision', 'numeric', 'real', 'float'].includes(expression.to.name) ? 'double'
        : ['text', 'varchar', 'character varying'].includes(expression.to.name) ? 'string' : expression.to.name === 'boolean' ? 'bool' : ['timestamptz', 'timestamp', 'date'].includes(expression.to.name) ? 'date' : null;
      if (!target) throw new TypeError(`MongoDB query cast is not supported: ${expression.to.name}`);
      return { value: { $convert: { input: result.value, to: target, onNull: null } }, stages: result.stages };
    }
    case 'member': {
      const input = jsonExpression(expression.operand, context);
      const value = { $getField: { field: literal(String(expression.member)), input: input.value } };
      return { value: expression.op === '->>' ? { $convert: { input: value, to: 'string', onNull: null } } : value, stages: input.stages };
    }
    case 'list': case 'array': {
      const result = combined(expression.expressions, context);
      return { value: result.values, stages: result.stages };
    }
    case 'unary': {
      const result = compileExpression(expression.operand, context);
      const operators: Record<string, MongoValue> = {
        'IS NULL': { $eq: [{ $ifNull: [result.value, null] }, null] },
        'IS NOT NULL': { $ne: [{ $ifNull: [result.value, null] }, null] },
        NOT: { $not: [result.value] }, '-': { $multiply: [-1, result.value] }, '+': result.value,
        'IS TRUE': { $eq: [result.value, true] }, 'IS FALSE': { $eq: [result.value, false] },
        'IS NOT TRUE': { $ne: [result.value, true] }, 'IS NOT FALSE': { $ne: [result.value, false] },
      };
      if (!(expression.op in operators)) throw new TypeError(`Unsupported MongoDB unary operator: ${expression.op}`);
      return { value: operators[expression.op]!, stages: result.stages };
    }
    case 'binary': {
      if (expression.op === '#>>') {
        if (expression.right.type !== 'string' || !/^\{[^{}]*\}$/.test(expression.right.value)) throw new TypeError('JSON path operators require a literal path');
        return compileCall({ type: 'call', function: { name: 'jsonb_extract_path_text' }, args: [expression.left, ...expression.right.value.slice(1, -1).split(',').map(value => ({ type: 'string' as const, value }))] }, context);
      }
      const left = compileExpression(expression.left, context);
      const isQuery = ['select', 'with', 'union', 'union all'].includes(expression.right.type);
      const right = isQuery && ['IN', 'NOT IN'].includes(expression.op) ? subquery(expression.right as SelectStatement, context) : compileExpression(expression.right, context);
      const args = [left.value, ['IN', 'NOT IN'].includes(expression.op) && !isQuery && expression.right.type !== 'list' ? [right.value] : right.value];
      const operators: Record<string, string> = { '=': '$eq', '!=': '$ne', '<>': '$ne', '>': '$gt', '<': '$lt', '>=': '$gte', '<=': '$lte', AND: '$and', OR: '$or', '+': '$add', '-': '$subtract', '*': '$multiply', '/': '$divide', '%': '$mod', '||': '$concat', IN: '$in' };
      let value: MongoValue;
      if (expression.op === 'NOT IN') value = { $not: [{ $in: args }] };
      else if (expression.op.includes('LIKE')) {
        const pattern = expression.right.type === 'parameter' ? context.values[Number(expression.right.name.slice(1)) - 1] : expression.right.type === 'string' ? expression.right.value : null;
        if (typeof pattern !== 'string') throw new TypeError('MongoDB LIKE requires a string literal or parameter');
        let regex = '^';
        let escaped = false;
        for (const character of pattern) {
          if (!escaped && character === '\\') { escaped = true; continue; }
          regex += !escaped && character === '%' ? '.*' : !escaped && character === '_' ? '.' : character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          escaped = false;
        }
        const match = { $regexMatch: { input: { $ifNull: [left.value, ''] }, regex: regex + '$', options: expression.op.includes('ILIKE') ? 'i' : '' } };
        value = expression.op.startsWith('NOT') ? { $not: [match] } : match;
      } else {
        const operator = operators[expression.op];
        if (!operator) throw new TypeError(`MongoDB query operator is not supported: ${expression.op}`);
        value = { [operator]: args };
        if (['=', '!=', '<>', '>', '<', '>=', '<='].includes(expression.op)) value = { $and: [{ $ne: [left.value, null] }, { $ne: [right.value, null] }, value] };
      }
      return { value, stages: [...left.stages, ...right.stages] };
    }
    case 'ternary': {
      const result = combined([expression.value, expression.lo, expression.hi], context);
      const range: MongoValue = { $and: [{ $gte: [result.values[0]!, result.values[1]!] }, { $lte: [result.values[0]!, result.values[2]!] }] };
      return { value: expression.op === 'NOT BETWEEN' ? { $not: [range] } : range, stages: result.stages };
    }
    case 'case': {
      const input = expression.value ? compileExpression(expression.value, context) : null;
      const branches = expression.whens.map(branch => ({ when: compileExpression(branch.when, context), value: compileExpression(branch.value, context) }));
      const otherwise = expression.else ? compileExpression(expression.else, context) : { value: null, stages: [] };
      return { value: { $switch: { branches: branches.map(branch => ({ case: input ? { $eq: [input.value, branch.when.value] } : branch.when.value, then: branch.value.value })), default: otherwise.value } }, stages: [...(input?.stages ?? []), ...branches.flatMap(branch => [...branch.when.stages, ...branch.value.stages]), ...otherwise.stages] };
    }
    case 'call': return compileCall(expression, context);
    case 'select': case 'with': case 'union': case 'union all': {
      const result = subquery(expression, context);
      return { value: { $ifNull: [{ $first: result.value }, null] }, stages: result.stages };
    }
    default: throw new TypeError(`MongoDB query expression is not supported: ${expression.type}`);
  }
}

function aggregateCalls(expression: Expr): ExprCall[] {
  if (expression.type === 'select' || expression.type === 'with') return [];
  if (expression.type === 'call') return aggregateNames.has(expression.function.name) ? [expression] : expression.args.flatMap(aggregateCalls);
  if (expression.type === 'cast' || expression.type === 'unary' || expression.type === 'member') return aggregateCalls(expression.operand);
  if (expression.type === 'binary') return [...aggregateCalls(expression.left), ...aggregateCalls(expression.right)];
  if (expression.type === 'case') return [...expression.whens.flatMap(branch => [...aggregateCalls(branch.when), ...aggregateCalls(branch.value)]), ...(expression.else ? aggregateCalls(expression.else) : [])];
  return [];
}

function columnName(column: SelectedColumn): string {
  if (column.alias) return column.alias.name;
  if (column.expr.type === 'ref') return column.expr.name;
  if (column.expr.type === 'call') return column.expr.function.name;
  if (column.expr.type === 'integer') return '?column?';
  throw new TypeError('Computed query columns require an explicit alias');
}

export function compileSelect(statement: SelectStatement, values: StoredValue[], ctes: Record<string, SelectStatement>, outer: Record<string, Reference>): QueryPlan {
  if (statement.type === 'with') {
    const bindings = Object.fromEntries(statement.bind.map(binding => {
      if (!['select', 'with', 'union', 'union all', 'values'].includes(binding.statement.type)) throw new TypeError('MongoDB CTEs must contain read queries');
      return [binding.alias.name, binding.statement as SelectStatement];
    }));
    return compileSelect(statement.in as SelectStatement, values, { ...ctes, ...bindings }, outer);
  }
  if (statement.type === 'union' || statement.type === 'union all') {
    const left = compileSelect(statement.left, values, ctes, outer);
    const right = compileSelect(statement.right, values, ctes, outer);
    return { ...left, pipeline: [...left.pipeline, { $unionWith: { ...(right.collection ? { coll: right.collection } : {}), pipeline: right.pipeline } }, ...(statement.type === 'union' ? [{ $group: { _id: '$$ROOT' } }, { $replaceWith: '$_id' }] : [])] };
  }
  if (statement.type !== 'select') throw new TypeError(`MongoDB read statement is not supported: ${statement.type}`);
  const sources = statement.from ?? [];
  const first = sources[0];
  let collection: string | null = null;
  let pipeline: MongoStage[] = [];
  let references: Record<string, Reference> = { ...outer };
  for (const [index, source] of sources.entries()) {
    let plan: QueryPlan;
    let alias: string;
    if (source.type === 'table') {
      const definition = COLLECTIONS[source.name.name];
      const cte = ctes[source.name.name];
      alias = source.name.alias ?? source.name.name;
      if (cte) plan = compileSelect(cte, values, ctes, outer);
      else {
        if (!definition) throw new TypeError(`MongoDB collection is not defined: ${source.name.name}`);
        plan = { collection: source.name.name, pipeline: [], columns: Object.keys(definition.columns) };
      }
    } else if (source.type === 'statement') {
      alias = source.alias;
      plan = compileSelect(source.statement, values, ctes, outer);
    } else throw new TypeError('MongoDB FROM functions are not supported');
    if (index === 0) {
      collection = plan.collection;
      pipeline = [...plan.pipeline, { $replaceWith: { [alias]: '$$ROOT' } }];
      references = { ...references, [alias]: { path: '$' + alias, columns: plan.columns } };
    } else {
      if (source.join?.type && !['INNER JOIN', 'LEFT JOIN', 'CROSS JOIN'].includes(source.join.type)) throw new TypeError(`MongoDB join is not supported: ${source.join.type}`);
      const current = Object.entries(references);
      const inside = Object.fromEntries(current.map(([name, ref], position) => [name, { ...ref, path: `$$join${position}` }]));
      const joinContext: Context = { references: { ...inside, [alias]: { path: '$$ROOT', columns: plan.columns } }, values, ctes, grouped: {} };
      const condition = source.join?.on ? compileExpression(source.join.on, joinContext) : { value: true, stages: [] };
      pipeline.push({ $lookup: { ...(plan.collection ? { from: plan.collection } : {}), let: Object.fromEntries(current.map(([, ref], position) => [`join${position}`, ref.path])), pipeline: [...plan.pipeline, ...condition.stages, { $match: { $expr: condition.value } }], as: alias } }, { $unwind: { path: '$' + alias, preserveNullAndEmptyArrays: source.join?.type === 'LEFT JOIN' } });
      references = { ...references, [alias]: { path: '$' + alias, columns: plan.columns } };
    }
  }
  if (!first) pipeline = [{ $documents: [{}] }];
  let context: Context = { references, values, ctes, grouped: {} };
  if (statement.where) {
    const condition = compileExpression(statement.where, context);
    pipeline.push(...condition.stages, { $match: { $expr: condition.value } });
  }
  const columns = statement.columns ?? [{ expr: { type: 'ref', name: '*' } }];
  const calls = [...new Map([...columns.flatMap(column => aggregateCalls(column.expr)), ...(statement.having ? aggregateCalls(statement.having) : [])].map(call => [expressionKey(call), call])).values()];
  if (calls.length || statement.groupBy?.length) {
    const groups = (statement.groupBy ?? []).map(expression => expression.type === 'integer' ? columns[expression.value - 1]?.expr ?? expression : expression.type === 'ref' && !expression.table ? columns.find(column => column.alias?.name === expression.name)?.expr ?? expression : expression).map(expression => ({ expression, compiled: compileExpression(expression, context) }));
    const accumulators: Record<string, MongoValue> = {};
    const grouped: Record<string, string> = Object.fromEntries(groups.map((group, index) => [expressionKey(group.expression), `$_id.group${index}`]));
    const defaults: Record<string, MongoValue> = { _id: null };
    for (const [index, call] of calls.entries()) {
      const key = 'aggregate' + index;
      const name = call.function.name;
      const arg = call.args[0];
      const argument = arg && !(arg.type === 'ref' && arg.name === '*') ? compileExpression(arg, context) : { value: 1, stages: [] };
      const filter = call.filter ? compileExpression(call.filter, context) : null;
      pipeline.push(...argument.stages, ...(filter?.stages ?? []));
      const value = filter ? { $cond: [filter.value, argument.value, null] } : argument.value;
      if (name === 'count') {
        const condition = arg?.type === 'ref' && arg.name === '*' ? true : { $ne: [argument.value, null] };
        accumulators[key] = call.distinct === 'distinct' ? { $addToSet: value } : { $sum: { $cond: [filter ? { $and: [filter.value, condition] } : condition, 1, 0] } };
        grouped[expressionKey(call)] = call.distinct === 'distinct' ? key : '$' + key;
        defaults[key] = call.distinct === 'distinct' ? [] : 0;
      } else if (['sum', 'avg', 'min', 'max'].includes(name)) {
        accumulators[key] = { ['$' + name]: value };
        grouped[expressionKey(call)] = '$' + key;
        defaults[key] = null;
      } else if (name === 'array_agg' || name === 'string_agg') {
        accumulators[key] = { [call.distinct === 'distinct' ? '$addToSet' : '$push']: value };
        grouped[expressionKey(call)] = '$' + key;
        defaults[key] = null;
      }
    }
    const groupStage: MongoStage = { $group: { _id: groups.length ? Object.fromEntries(groups.map((group, index) => ['group' + index, group.compiled.value])) : null, row: { $first: '$$ROOT' }, ...accumulators } };
    pipeline.push(...groups.flatMap(group => group.compiled.stages), ...(groups.length ? [groupStage] : [{ $facet: { aggregate: [groupStage] } }, { $replaceWith: { $ifNull: [{ $first: '$aggregate' }, { $literal: defaults }] } }] as MongoStage[]));
    for (const [index, call] of calls.entries()) if (call.function.name === 'count' && call.distinct === 'distinct') pipeline.push({ $set: { ['aggregate' + index]: { $size: { $setDifference: ['$aggregate' + index, [null]] } } } });
    for (const call of calls) if (call.function.name === 'count' && call.distinct === 'distinct') grouped[expressionKey(call)] = '$' + grouped[expressionKey(call)]!;
    context = { ...context, references: Object.fromEntries(Object.entries(references).map(([name, ref]) => [name, { ...ref, path: ref.path.startsWith('$$') ? ref.path : '$row.' + ref.path.slice(1) }])), grouped };

  }
  if (statement.having) {
    const condition = compileExpression(statement.having, context);
    pipeline.push(...condition.stages, { $match: { $expr: condition.value } });
  }
  const sorts = (statement.orderBy ?? []).map(order => {
    const selected = order.by.type === 'ref' && !order.by.table ? columns.find(column => column.alias?.name === (order.by as { name: string }).name) : undefined;
    return { order: order.order === 'DESC' ? -1 : 1, compiled: compileExpression(order.by.type === 'integer' ? columns[order.by.value - 1]?.expr ?? order.by : selected?.expr ?? order.by, context) };
  });
  if (sorts.length) pipeline.push(...sorts.flatMap(sort => sort.compiled.stages), { $set: Object.fromEntries(sorts.map((sort, index) => ['sort' + index, sort.compiled.value])) }, { $sort: Object.fromEntries(sorts.map((sort, index) => ['sort' + index, sort.order])) });
  const selectedNames: string[] = [];
  const selected: Record<string, MongoValue> = {};
  const selectedJson: Record<string, MongoValue> = {};
  const stars: MongoValue[] = [];
  for (const column of columns) {
    if (column.expr.type === 'ref' && column.expr.name === '*') {
      const names = column.expr.table ? [column.expr.table.name] : sources.map(source => source.type === 'table' ? source.name.alias ?? source.name.name : source.type === 'statement' ? source.alias : '');
      for (const name of names) {
        const source = references[name];
        if (!source) throw new TypeError(`Unknown wildcard query source: ${name}`);
        stars.push(source.path);
        selectedNames.push(...source.columns);
      }
    } else {
      const name = columnName(column);
      const compiled = compileExpression(column.expr, context);
      pipeline.push(...compiled.stages);
      selected[name] = { $ifNull: [compiled.value, null] };
      if (column.expr.type === 'ref') selectedJson[name] = jsonExpression(column.expr, context).value;
      selectedNames.push(name);
    }
  }
  if (stars.length) pipeline.push({ $replaceWith: { $mergeObjects: [...stars, selected] } }, { $unset: '_id' });
  else pipeline.push({ $project: { _id: 0, ...selected, __json: Object.keys(selectedJson).length ? selectedJson : { $literal: {} } } });
  if (statement.distinct === 'distinct') pipeline.push({ $group: { _id: '$$ROOT' } }, { $replaceWith: '$_id' });
  if (statement.limit?.offset) pipeline.push({ $skip: scalar(statement.limit.offset, values) as number });
  if (statement.limit?.limit) {
    const limit = scalar(statement.limit.limit, values);
    if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 0) throw new TypeError('MongoDB query limit must be a nonnegative integer');
    pipeline.push(limit === 0 ? { $match: { $expr: false } } : { $limit: limit });
  }
  return { collection, pipeline, columns: [...new Set(selectedNames)] };
}

export function scalar(expression: Expr, values: StoredValue[]): StoredValue {
  if (expression.type === 'parameter') {
    const index = Number(expression.name.slice(1)) - 1;
    if (index < 0 || index >= values.length) throw new RangeError(`Missing query parameter ${expression.name}`);
    return values[index]!;
  }
  if (expression.type === 'null') return null;
  if (['string', 'integer', 'numeric', 'boolean'].includes(expression.type)) return (expression as { value: StoredValue }).value;
  if (expression.type === 'unary' && expression.op === '-') {
    const value = scalar(expression.operand, values);
    if (typeof value !== 'number') throw new TypeError('A negated database value must be numeric');
    return -value;
  }
  if (expression.type === 'cast') return scalar(expression.operand, values);
  throw new TypeError(`A stored value must be a literal or parameter, received ${expression.type}`);
}

export function compileDocumentExpression(expression: Expr, table: string, aliases: string[], values: StoredValue[]): CompiledExpression {
  const definition = COLLECTIONS[table];
  if (!definition) throw new TypeError(`MongoDB collection is not defined: ${table}`);
  return compileExpression(expression, { references: Object.fromEntries([table, ...aliases].map(alias => [alias, { path: '$$ROOT', columns: Object.keys(definition.columns) }])), values, ctes: {}, grouped: {} });
}

export function compileAssignedExpression(expression: Expr, table: string, alias: string, values: StoredValue[]): CompiledExpression {
  const definition = COLLECTIONS[table];
  if (!definition) throw new TypeError(`MongoDB collection is not defined: ${table}`);
  return compileExpression(expression, { references: {
    [table]: { path: '$$ROOT', columns: Object.keys(definition.columns) },
    [alias]: { path: '$$ROOT', columns: Object.keys(definition.columns) },
    excluded: { path: '$excluded', columns: Object.keys(definition.columns) },
  }, values, ctes: {}, grouped: {} });
}
