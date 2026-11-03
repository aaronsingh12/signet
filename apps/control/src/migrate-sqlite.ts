import { backup, DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DATA_DIR } from '@signet/core';
import { db, tx } from './db';
import { SCHEMA_TABLES } from './schema';
import type { SqlValue } from './postgres';

interface Table { name: string }
interface ForeignKey { table: string }

function identifier(value: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(value)) throw new TypeError(`Invalid migration identifier: ${value}`);
  return `"${value}"`;
}

/** Copy a consistent SQLite snapshot to an empty PostgreSQL schema without changing source records. */
async function migrate(): Promise<void> {
  const sourceFile = join(DATA_DIR, 'signet.db');
  if (!existsSync(sourceFile)) throw new Error(`SQLite migration source does not exist: ${sourceFile}`);
  const source = new DatabaseSync(sourceFile, { readOnly: true });
  const directory = join(DATA_DIR, 'backups');
  mkdirSync(directory, { recursive: true });
  const snapshotFile = join(directory, `signet-before-postgres-${Date.now()}.db`);
  try { await backup(source, snapshotFile); }
  finally { source.close(); }
  const snapshot = new DatabaseSync(snapshotFile, { readOnly: true });
  try {
    const tables = snapshot.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as unknown as Table[];
    const ordered: string[] = [];
    const remaining = new Set(tables.map((table) => table.name));
    while (remaining.size) {
      const ready = [...remaining].filter((name) => (snapshot.prepare(`PRAGMA foreign_key_list(${identifier(name)})`).all() as unknown as ForeignKey[]).every((key) => !remaining.has(key.table)));
      if (!ready.length) throw new Error(`SQLite foreign-key dependency cycle: ${[...remaining].join(', ')}`);
      for (const name of ready) { ordered.push(name); remaining.delete(name); }
    }
    const counts: { table: string; rows: number }[] = [];
    await tx(async () => {
      for (const name of ordered) {
        if (!SCHEMA_TABLES.has(name)) throw new Error(`PostgreSQL schema has no migration destination for SQLite table ${name}`);
        const count = await db.prepare(`SELECT COUNT(*) AS n FROM ${identifier(db.schema)}.${identifier(name)}`).get() as { n: number };
        if (count.n !== 0) throw new Error(`PostgreSQL table ${name} already has ${count.n} records; migration requires an empty destination and will not overwrite data`);
      }
      for (const name of ordered) {
        const rows = snapshot.prepare(`SELECT * FROM ${identifier(name)}`).all();
        for (const row of rows) {
          const columns = Object.keys(row);
          const values = columns.map((column): SqlValue => {
            const value = row[column];
            if (value === null || typeof value === 'string' || typeof value === 'number') return value;
            throw new TypeError(`SQLite ${name}.${column} has an unsupported migration value type: ${typeof value}`);
          });
          await db.prepare(`INSERT INTO ${identifier(db.schema)}.${identifier(name)} (${columns.map(identifier).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`).run(...values);
        }
        const count = await db.prepare(`SELECT COUNT(*) AS n FROM ${identifier(db.schema)}.${identifier(name)}`).get() as { n: number };
        if (count.n !== rows.length) throw new Error(`Migration verification failed for ${name}: expected ${rows.length}, found ${count.n}`);
        counts.push({ table: name, rows: count.n });
      }
      const original = snapshot.prepare('SELECT seq, record_hash, prev_hash, data FROM ledger_record ORDER BY seq').all();
      const migrated = await db.prepare('SELECT seq, record_hash, prev_hash, data FROM ledger_record ORDER BY seq').all();
      if (JSON.stringify(original.map((row) => ({ seq: row.seq, record_hash: row.record_hash, prev_hash: row.prev_hash, data: row.data }))) !== JSON.stringify(migrated)) throw new Error('Ledger migration changed signed data or chain hashes; transaction rolled back');
    });
    console.log('SQLite data migrated to PostgreSQL', { tables: counts.length, records: counts.reduce((total, item) => total + item.rows, 0), snapshot: snapshotFile });
    console.log(JSON.stringify(counts));
  } finally { snapshot.close(); }
}

try { await migrate(); }
finally { await db.close(); }
