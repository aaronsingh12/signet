import { DATA_DIR } from '@signet/core';
import { mkdirSync } from 'node:fs';
import { MongoDatabase } from './mongodb';

mkdirSync(DATA_DIR, { recursive: true });
const connectionString = process.env.MONGODB_URL;
if (!connectionString) throw new Error('MONGODB_URL is required in the repository root .env; start the local replica set with npm run mongo:start');
const configuredName = new URL(connectionString).pathname.slice(1);
if (!configuredName) throw new Error('MONGODB_URL must include a database name');
export const db = new MongoDatabase(connectionString, process.env.MONGODB_DATABASE ?? configuredName);
console.info('Initializing MongoDB collections', { database: db.name });
await db.initialize();
console.info('MongoDB collections ready', { database: db.name });

export const nowIso = (): string => new Date().toISOString();
export const tx = <T>(operation: () => Promise<T>): Promise<T> => db.transaction(operation);
