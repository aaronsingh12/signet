import { DATA_DIR } from '@signet/core';
import { mkdirSync } from 'node:fs';
import { PostgresDatabase } from './postgres';
import { SCHEMA_SQL } from './schema';

mkdirSync(DATA_DIR, { recursive: true });
const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error('DATABASE_URL is required: configure the Neon PostgreSQL connection string in .env');
export const db = new PostgresDatabase(connectionString, process.env.SIGNET_DB_SCHEMA ?? 'public');
await db.initialize(SCHEMA_SQL);

export const nowIso = (): string => new Date().toISOString();
export const tx = <T>(operation: () => Promise<T>): Promise<T> => db.transaction(operation);
