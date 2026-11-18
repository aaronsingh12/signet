import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { MongoClient, type ClientSession, type Collection } from 'mongodb';
import { parse, type DeleteStatement, type InsertStatement, type SelectedColumn, type Statement, type UpdateStatement } from 'pgsql-ast-parser';
import { COLLECTIONS, type StoredValue } from './mongodb-schema';
import { compileAssignedExpression, compileDocumentExpression, compileSelect, scalar, type MongoStage, type MongoValue, type QueryPlan } from './mongodb-query';

type Row = Record<string, StoredValue>;
interface StoredDocument { _id: string; [key: string]: MongoValue }
interface Result { rows: Row[]; changes: number }
interface Transaction { session: ClientSession; ledgerErasure: boolean }

function parameters(sql: string): string {
  let position = 0;
  let quoted = false;
  let result = '';
  for (let index = 0; index < sql.length; index++) {
    const character = sql[index]!;
    if (character === "'") {
      if (quoted && sql[index + 1] === "'") { result += "''"; index++; continue; }
      quoted = !quoted;
    }
    result += character === '?' && !quoted ? '$' + ++position : character;
  }
  return result;
}

function checkedRow(document: { [key: string]: MongoValue }): Row {
  return Object.fromEntries(Object.entries(document).filter(([name]) => name !== '_id' && name !== '__json').map(([name, value]) => {
    if (value !== null && !['string', 'number', 'boolean'].includes(typeof value)) throw new TypeError(`MongoDB query returned a non-scalar field: ${name}`);
    return [name, value as StoredValue];
  }));
}

function jsonFields(document: Row): { [key: string]: MongoValue } {
  return Object.fromEntries(Object.entries(document).flatMap(([name, value]) => {
    if (typeof value !== 'string' || !/^[\[{]/.test(value.trim())) return [];
    try { return [[name, JSON.parse(value) as MongoValue]]; }
    catch (error) { if (error instanceof SyntaxError) return []; throw error; }
  }));
}

function returned(document: StoredDocument, columns: SelectedColumn[]): Row {
  if (columns.some(column => column.expr.type === 'ref' && column.expr.name === '*')) return checkedRow(document);
  return Object.fromEntries(columns.map(column => {
    if (column.expr.type !== 'ref') throw new TypeError('MongoDB mutation RETURNING requires named fields');
    return [column.alias?.name ?? column.expr.name, document[column.expr.name] as StoredValue ?? null];
  }));
}

/** Persists application collections in MongoDB and executes the existing query interface as native operations. */
export class MongoDatabase {
  private readonly client: MongoClient;
  private readonly context = new AsyncLocalStorage<Transaction>();

  constructor(connectionString: string, readonly name: string) {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(name)) throw new TypeError('MONGODB_DATABASE must be a lowercase identifier of at most 63 characters');
    if (!/^mongodb(?:\+srv)?:\/\//.test(connectionString)) throw new TypeError('MONGODB_URL must be a MongoDB connection URI');
    this.client = new MongoClient(connectionString, { maxPoolSize: 10, serverSelectionTimeoutMS: 5000 });
  }

  private collection(name: string): Collection<StoredDocument> {
    if (!COLLECTIONS[name]) throw new TypeError(`MongoDB collection is not defined: ${name}`);
    return this.client.db(this.name).collection<StoredDocument>(name);
  }

  async initialize(): Promise<void> {
    for (let attempt = 1; ; attempt++) {
      try { await this.client.connect(); break; }
      catch (error) {
        console.warn('MongoDB connection failed', { database: this.name, attempt, error: error instanceof Error ? error.message : String(error) });
        if (attempt >= 3) throw error;
        await setTimeout(attempt * 300);
      }
    }
    const hello = await this.client.db('admin').command({ hello: 1 });
    if (!hello.setName && hello.msg !== 'isdbgrid') throw new Error('MongoDB must run as a replica set to support Signet transactions; start local MongoDB with npm run mongo:start');
    const existing = new Set((await this.client.db(this.name).listCollections({}, { nameOnly: true }).toArray()).map(collection => collection.name));
    for (const [name, definition] of Object.entries(COLLECTIONS)) {
      if (!existing.has(name)) await this.client.db(this.name).createCollection(name);
      const collection = this.collection(name);
      for (const [index, columns] of definition.unique.entries()) {
        const nullable = columns.filter(column => !definition.columns[column]?.required);
        await collection.createIndex(Object.fromEntries(columns.map(column => [column, 1])), {
          name: 'unique_' + index, unique: true,
          ...(nullable.length ? { partialFilterExpression: { $and: nullable.map(column => ({ [column]: { $type: ['string', 'number', 'bool'] } })) } } : {}),
        });
      }
      for (const [index, keys] of definition.indexes.entries()) await collection.createIndex(keys, { name: 'lookup_' + index });
    }
    await this.client.db(this.name).collection<{ _id: string; revision: number }>('_transactions').updateOne({ _id: 'write' }, { $setOnInsert: { revision: 0 } }, { upsert: true });
  }

  async transaction<T>(operation: () => Promise<T>): Promise<T> {
    if (this.context.getStore()) return operation();
    const session = this.client.startSession();
    let attempt = 0;
    try {
      return await session.withTransaction(async () => {
        if (++attempt > 1) console.warn('MongoDB transaction retry', { database: this.name, attempt });
        await this.client.db(this.name).collection<{ _id: string; revision: number }>('_transactions').updateOne({ _id: 'write' }, { $inc: { revision: 1 } }, { session });
        return this.context.run({ session, ledgerErasure: false }, operation);
      }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
    } finally { await session.endSession(); }
  }

  prepare(query: string): {
    all: (...values: StoredValue[]) => Promise<Row[]>;
    get: (...values: StoredValue[]) => Promise<Row | undefined>;
    run: (...values: StoredValue[]) => Promise<{ changes: number }>;
  } {
    const sql = parameters(query);
    let statement: Statement;
    try {
      const parsed = parse(sql);
      if (parsed.length !== 1) throw new TypeError('Exactly one database statement is required');
      statement = parsed[0]!;
    } catch (error) { throw new Error(`MongoDB query could not be compiled: ${sql.slice(0, 240)}`, { cause: error }); }
    return {
      all: async (...values): Promise<Row[]> => (await this.execute(statement, values)).rows,
      get: async (...values): Promise<Row | undefined> => (await this.execute(statement, values)).rows[0],
      run: async (...values): Promise<{ changes: number }> => ({ changes: (await this.execute(statement, values)).changes }),
    };
  }

  private async read(plan: QueryPlan): Promise<Row[]> {
    const session = this.context.getStore()?.session;
    const rows = plan.collection
      ? await this.collection(plan.collection).aggregate<{ [key: string]: MongoValue }>(plan.pipeline, { session, maxTimeMS: 30000 }).toArray()
      : await this.client.db(this.name).aggregate<{ [key: string]: MongoValue }>(plan.pipeline, { session, maxTimeMS: 30000 }).toArray();
    return rows.map(checkedRow);
  }

  private async execute(statement: Statement, values: StoredValue[]): Promise<Result> {
    if (['select', 'with', 'union', 'union all'].includes(statement.type)) {
      const rows = await this.read(compileSelect(statement as Parameters<typeof compileSelect>[0], values, {}, {}));
      return { rows, changes: rows.length };
    }
    return this.transaction(async () => {
      if (statement.type === 'insert') return this.insert(statement, values);
      if (statement.type === 'update') return this.update(statement, values);
      if (statement.type === 'delete') return this.remove(statement, values);
      throw new TypeError(`MongoDB database statement is not supported: ${statement.type}`);
    });
  }

  private normalized(table: string, row: Row, id: string): StoredDocument {
    const definition = COLLECTIONS[table];
    if (!definition) throw new TypeError(`MongoDB collection is not defined: ${table}`);
    for (const key of Object.keys(row)) if (!definition.columns[key]) throw new TypeError(`MongoDB collection ${table} has no field ${key}`);
    const fields = Object.fromEntries(Object.entries(definition.columns).map(([name, column]) => {
      const value = name in row ? row[name]! : column.value;
      if (column.required && value === null) throw new TypeError(`MongoDB collection ${table} requires field ${name}`);
      if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError(`MongoDB field ${table}.${name} must be finite`);
      return [name, value];
    }));
    return { ...fields, _id: id, __json: jsonFields(fields) };
  }

  private async references(table: string, document: StoredDocument): Promise<void> {
    for (const reference of COLLECTIONS[table]!.references) {
      if (reference.columns.some(column => document[column] === null)) continue;
      const filter = Object.fromEntries(reference.foreignColumns.map((column, index) => [column, document[reference.columns[index]!]!]));
      if (!await this.collection(reference.table).findOne(filter, { session: this.context.getStore()?.session, projection: { _id: 1 } })) throw new Error(`MongoDB relationship failed: ${table}.${reference.columns.join(',')} references a missing ${reference.table} record`);
    }
  }

  private documentProjection(table: string): MongoStage {
    return { $project: { _id: 1, __json: 1, ...Object.fromEntries(Object.keys(COLLECTIONS[table]!.columns).map(column => [column, 1])) } };
  }

  private async conflict(table: string, document: StoredDocument, statement: InsertStatement): Promise<StoredDocument | null> {
    const explicit = statement.onConflict?.on;
    const indexes = explicit?.type === 'on expr' ? [explicit.exprs.map(expression => {
      if (expression.type !== 'ref') throw new TypeError('MongoDB conflict keys must be field names');
      return expression.name;
    })] : COLLECTIONS[table]!.unique;
    for (const columns of indexes) {
      if (columns.some(column => document[column] === null)) continue;
      const existing = await this.collection(table).findOne(Object.fromEntries(columns.map(column => [column, document[column]!])), { session: this.context.getStore()?.session });
      if (existing) return existing;
    }
    return null;
  }

  private async insert(statement: InsertStatement, values: StoredValue[]): Promise<Result> {
    const table = statement.into.name;
    const columns = statement.columns?.map(column => column.name) ?? Object.keys(COLLECTIONS[table]!.columns);
    const inputs = statement.insert.type === 'values'
      ? statement.insert.values.map(row => Object.fromEntries(row.map((expression, index) => [columns[index]!, scalar(expression, values)])))
      : await this.read(compileSelect(statement.insert, values, {}, {}));
    const rows: Row[] = [];
    let changes = 0;
    for (const input of inputs) {
      const document = this.normalized(table, input, randomUUID());
      const previous = statement.onConflict ? await this.conflict(table, document, statement) : null;
      if (previous && statement.onConflict?.do === 'do nothing') continue;
      if (previous && statement.onConflict && typeof statement.onConflict.do === 'object') {
        this.assertUpdatable(table, previous);
        const sets = statement.onConflict.do.sets;
        const expressions = sets.map(set => ({ name: set.column.name, result: compileAssignedExpression(set.value, table, statement.into.alias ?? table, values) }));
        const pipeline: MongoStage[] = [{ $match: { _id: previous._id } }, { $set: { excluded: { $literal: document } } }, ...expressions.flatMap(expression => expression.result.stages), { $set: Object.fromEntries(expressions.map(expression => [expression.name, expression.result.value])) }, { $unset: 'excluded' }, this.documentProjection(table)];
        const updated = (await this.collection(table).aggregate<StoredDocument>(pipeline, { session: this.context.getStore()?.session }).toArray())[0];
        if (!updated) throw new Error(`MongoDB upsert lost its existing ${table} record`);
        const normalized = this.normalized(table, checkedRow(updated), previous._id);
        await this.references(table, normalized);
        await this.collection(table).replaceOne({ _id: previous._id }, normalized, { session: this.context.getStore()?.session });
        if (statement.returning) rows.push(returned(normalized, statement.returning));
      } else {
        await this.references(table, document);
        await this.collection(table).insertOne(document, { session: this.context.getStore()?.session });
        if (statement.returning) rows.push(returned(document, statement.returning));
      }
      changes++;
    }
    return { rows, changes };
  }

  private async update(statement: UpdateStatement, values: StoredValue[]): Promise<Result> {
    const table = statement.table.name;
    const condition = statement.where ? compileDocumentExpression(statement.where, table, [statement.table.alias ?? table], values) : { value: true, stages: [] };
    const expressions = statement.sets.map(set => ({ name: set.column.name, result: compileAssignedExpression(set.value, table, statement.table.alias ?? table, values) }));
    const pipeline: MongoStage[] = [...condition.stages, { $match: { $expr: condition.value } }, ...expressions.flatMap(expression => expression.result.stages), { $set: Object.fromEntries(expressions.map(expression => [expression.name, expression.result.value])) }, this.documentProjection(table)];
    const documents = await this.collection(table).aggregate<StoredDocument>(pipeline, { session: this.context.getStore()?.session }).toArray();
    const rows: Row[] = [];
    for (const document of documents) {
      this.assertUpdatable(table, document);
      const normalized = this.normalized(table, checkedRow(document), document._id);
      await this.references(table, normalized);
      await this.collection(table).replaceOne({ _id: document._id }, normalized, { session: this.context.getStore()?.session });
      if (statement.returning) rows.push(returned(normalized, statement.returning));
    }
    return { rows, changes: documents.length };
  }

  private assertUpdatable(table: string, document: StoredDocument): void {
    if (table === 'ledger_record' && this.context.getStore()?.ledgerErasure) return;
    if (['ledger_record', 'daily_root', 'evidence_anchor'].includes(table) || (table === 'evidence_object' && typeof document.path === 'string' && document.path.startsWith('roots/'))) throw new Error(`${table} is append-only`);
  }

  private assertDeletable(table: string): void {
    if (['ledger_record', 'daily_root', 'evidence_anchor', 'evidence_object'].includes(table)) throw new Error(`${table} is append-only`);
  }

  private async erase(table: string, document: StoredDocument): Promise<void> {
    this.assertDeletable(table);
    for (const [other, definition] of Object.entries(COLLECTIONS)) for (const reference of definition.references.filter(reference => reference.table === table)) {
      const filter = Object.fromEntries(reference.columns.map((column, index) => [column, document[reference.foreignColumns[index]!]!]));
      const children = await this.collection(other).find(filter, { session: this.context.getStore()?.session }).toArray();
      if (!children.length) continue;
      if (reference.onDelete === 'cascade') for (const child of children) await this.erase(other, child);
      else if (reference.onDelete === 'set null') await this.collection(other).updateMany(filter, { $set: Object.fromEntries(reference.columns.map(column => [column, null])) }, { session: this.context.getStore()?.session });
      else throw new Error(`MongoDB deletion blocked: ${other}.${reference.columns.join(',')} still references ${table}`);
    }
    await this.collection(table).deleteOne({ _id: document._id }, { session: this.context.getStore()?.session });
  }

  private async remove(statement: DeleteStatement, values: StoredValue[]): Promise<Result> {
    const table = statement.from.name;
    const condition = statement.where ? compileDocumentExpression(statement.where, table, [statement.from.alias ?? table], values) : { value: true, stages: [] };
    const documents = await this.collection(table).aggregate<StoredDocument>([...condition.stages, { $match: { $expr: condition.value } }, this.documentProjection(table)], { session: this.context.getStore()?.session }).toArray();
    const rows: Row[] = [];
    for (const document of documents) {
      await this.erase(table, document);
      if (statement.returning) rows.push(returned(document, statement.returning));
    }
    return { rows, changes: documents.length };
  }

  async lock(): Promise<void> {
    if (!this.context.getStore()) throw new Error('MongoDB ledger and evidence locks require an active transaction');
  }

  async editErasedLedger<T>(operation: () => Promise<T>): Promise<T> {
    return this.transaction(async () => {
      const transaction = this.context.getStore();
      if (!transaction) throw new Error('MongoDB ledger erasure requires an active transaction');
      return this.context.run({ ...transaction, ledgerErasure: true }, operation);
    });
  }

  async exec(query: string): Promise<void> {
    if (/^TRUNCATE TABLE (ledger_record|daily_root|evidence_object|evidence_anchor)/i.test(query)) throw new Error('Evidence collections are append-only');
    throw new TypeError(`MongoDB does not execute database DDL: ${query.slice(0, 120)}`);
  }

  async drop(): Promise<void> { await this.client.db(this.name).dropDatabase(); }
  async close(): Promise<void> { await this.client.close(); }
}
