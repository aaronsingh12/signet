import { spawn } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { createConnection } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout } from 'node:timers/promises';
import { MongoClient, MongoNetworkError, MongoServerSelectionError } from 'mongodb';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
if (existsSync(resolve(root, '.env'))) process.loadEnvFile(resolve(root, '.env'));
const uri = process.env.MONGODB_URL;
if (!uri) throw new Error('MONGODB_URL is required in the repository root .env');
const address = new URL(uri);
if (address.protocol !== 'mongodb:' || address.hostname !== '127.0.0.1' || address.port !== '27017' || address.pathname !== '/signet' || address.searchParams.get('replicaSet') !== 'signet-local') {
  throw new Error('Local MongoDB requires MONGODB_URL=mongodb://127.0.0.1:27017/signet?replicaSet=signet-local');
}

async function serverListening(): Promise<boolean> {
  return new Promise((resolveListening, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port: 27017 });
    socket.once('connect', () => { socket.destroy(); resolveListening(true); });
    socket.once('error', (error: NodeJS.ErrnoException) => {
      socket.destroy();
      if (error.code === 'ECONNREFUSED') resolveListening(false);
      else reject(error);
    });
  });
}

async function connectLocal(client: MongoClient): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try { await client.connect(); return; }
    catch (error) {
      console.warn('Local MongoDB connection failed', { attempt, error: error instanceof Error ? error.message : String(error) });
      if (!(error instanceof MongoNetworkError || error instanceof MongoServerSelectionError) || attempt >= 10) throw error;
      await setTimeout(500);
    }
  }
}

if (!await serverListening()) {
  const binary = process.env.SIGNET_MONGODB_BINARY;
  if (!binary) throw new Error('SIGNET_MONGODB_BINARY must identify the local mongod executable in the root .env');
  const executable = resolve(root, binary);
  if (!existsSync(executable)) throw new Error(`Local MongoDB executable does not exist: ${executable}`);
  const dataDirectory = resolve(root, 'data/mongodb');
  mkdirSync(dataDirectory, { recursive: true });
  const server = spawn(executable, ['--bind_ip', '127.0.0.1', '--port', '27017', '--dbpath', dataDirectory,
    '--replSet', 'signet-local', '--logpath', resolve(dataDirectory, 'mongod.log'), '--logappend'],
  { cwd: root, detached: true, stdio: 'ignore', windowsHide: true });
  await new Promise<void>((resolveStarted, reject) => { server.once('spawn', resolveStarted); server.once('error', reject); });
  server.unref();
}

const direct = new MongoClient('mongodb://127.0.0.1:27017/?directConnection=true', { serverSelectionTimeoutMS: 2000 });
try {
  await connectLocal(direct);
  const hello = await direct.db('admin').command({ hello: 1 });
  if (hello.setName === undefined && hello.isreplicaset === true) {
    await direct.db('admin').command({ replSetInitiate: { _id: 'signet-local', members: [{ _id: 0, host: '127.0.0.1:27017' }] } });
  } else if (hello.setName !== 'signet-local') {
    throw new Error('MongoDB on port 27017 must run with --replSet signet-local; another standalone or replica set is using this port');
  }
} finally { await direct.close(); }
const client = new MongoClient(uri, { serverSelectionTimeoutMS: 3000 });
try {
  await connectLocal(client);
  await client.db('signet').command({ ping: 1 });
  console.info('Local MongoDB replica set ready', { host: '127.0.0.1', port: 27017, database: 'signet', replicaSet: 'signet-local' });
} finally { await client.close(); }
