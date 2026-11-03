/** Remove only this test process's isolated schema; the runtime public schema is never eligible. */
export async function dropTestDatabase(): Promise<void> {
  const { db } = await import('../src/db');
  if (!/^test_[a-z0-9_]+$/.test(db.schema) || db.schema !== process.env.SIGNET_DB_SCHEMA) throw new Error('Test cleanup refused: expected this process\'s isolated PostgreSQL schema');
  try { await db.exec(`DROP SCHEMA "${db.schema}" CASCADE`); }
  finally { await db.close(); }
}
