import { AsyncLocalStorage } from 'node:async_hooks';
import { setTimeout } from 'node:timers/promises';
import { Pool, types, type PoolClient, type QueryResult } from 'pg';
import { SCHEMA_TABLES } from './schema';

export type SqlValue = string | number | boolean | null;
type DatabaseRow = Record<string, SqlValue>;

function parameterized(sql: string): string {
  let index = 0;
  let quoted = false;
  let result = '';
  for (let position = 0; position < sql.length; position++) {
    const character = sql[position]!;
    if (character === "'") {
      if (quoted && sql[position + 1] === "'") { result += "''"; position++; continue; }
      quoted = !quoted;
    }
    result += character === '?' && !quoted ? `$${++index}` : character;
  }
  return result;
}

function numericValue(value: string): number {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new RangeError(`PostgreSQL returned a non-finite numeric value: ${value}`);
  return number;
}

function integerValue(value: string): number {
  const number = numericValue(value);
  if (!Number.isSafeInteger(number)) throw new RangeError(`PostgreSQL integer exceeds JavaScript's safe integer range: ${value}`);
  return number;
}

/** Qualify application tables so Neon transaction pooling never depends on session search_path. */
function qualified(sql: string, schema: string): string {
  return sql.replace(/'(?:''|[^'])*'|\b(FROM|JOIN|INTO|UPDATE|TABLE)\s+([a-z_][a-z0-9_]*)/gi, (match: string, keyword: string | undefined, table: string | undefined): string =>
    keyword && table && SCHEMA_TABLES.has(table) ? `${keyword} "${schema}".${table}` : match,
  );
}

/** PostgreSQL connector: transactions pin a client and nested operations share its async context. */
export class PostgresDatabase {
  private readonly pool: Pool;
  private readonly context = new AsyncLocalStorage<PoolClient>();

  constructor(connectionString: string, readonly schema: string) {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(schema)) throw new TypeError('SIGNET_DB_SCHEMA must be a lowercase PostgreSQL identifier of at most 63 characters');
    const url = new URL(connectionString);
    if (!['postgres:', 'postgresql:'].includes(url.protocol)) throw new TypeError('DATABASE_URL must be a PostgreSQL connection URL');
    url.searchParams.set('sslmode', 'verify-full');
    this.pool = new Pool({
      connectionString: url.toString(), enableChannelBinding: true, max: 10, connectionTimeoutMillis: 15_000,
      idleTimeoutMillis: 1000, allowExitOnIdle: true,
      types: { getTypeParser: (oid: number, format: 'text' | 'binary' | undefined) => {
        if (oid === 20) return integerValue;
        if (oid === 1700 || oid === 700 || oid === 701) return numericValue;
        return types.getTypeParser(oid, format);
      } },
    });
    this.pool.on('error', (error: Error) => console.error('PostgreSQL idle connection failed', { schema, error: error.message }));
  }

  private async acquire(): Promise<PoolClient> {
    for (let attempt = 1; ; attempt++) {
      try { return await this.pool.connect(); }
      catch (error) {
        console.warn('PostgreSQL connection failed', { schema: this.schema, attempt, error: error instanceof Error ? error.message : String(error) });
        if (attempt >= 3) throw error;
        await setTimeout(attempt * 300);
      }
    }
  }

  private async query(sql: string, values: SqlValue[]): Promise<QueryResult<DatabaseRow>> {
    const current = this.context.getStore();
    const query = parameterized(qualified(sql, this.schema));
    if (current) return current.query<DatabaseRow>(query, values);
    const client = await this.acquire();
    try { return await client.query<DatabaseRow>(query, values); }
    finally { client.release(); }
  }

  prepare(sql: string): {
    all: (...values: SqlValue[]) => Promise<DatabaseRow[]>;
    get: (...values: SqlValue[]) => Promise<DatabaseRow | undefined>;
    run: (...values: SqlValue[]) => Promise<{ changes: number }>;
  } {
    return {
      all: async (...values: SqlValue[]): Promise<DatabaseRow[]> => (await this.query(sql, values)).rows,
      get: async (...values: SqlValue[]): Promise<DatabaseRow | undefined> => (await this.query(sql, values)).rows[0],
      run: async (...values: SqlValue[]): Promise<{ changes: number }> => ({ changes: (await this.query(sql, values)).rowCount ?? 0 }),
    };
  }

  async exec(sql: string): Promise<void> {
    const current = this.context.getStore();
    const query = qualified(sql, this.schema);
    if (current) { await current.query(query); return; }
    const client = await this.acquire();
    try { await client.query(query); }
    finally { client.release(); }
  }

  async initialize(sql: string): Promise<void> {
    const client = await this.acquire();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [`${this.schema}:schema`]);
      await client.query(`CREATE SCHEMA IF NOT EXISTS "${this.schema}"`);
      await client.query(`SET LOCAL search_path TO "${this.schema}", public`);
      await client.query(sql);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  async transaction<T>(operation: () => Promise<T>): Promise<T> {
    if (this.context.getStore()) return operation();
    const client = await this.acquire();
    try {
      await client.query('BEGIN');
      const result = await this.context.run(client, operation);
      await client.query('COMMIT');
      return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }

  async close(): Promise<void> { await this.pool.end(); }
}
