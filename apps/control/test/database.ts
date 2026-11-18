/** Remove only this test process's isolated MongoDB database; the application database is never eligible. */
export async function dropTestDatabase(): Promise<void> {
  const { db } = await import('../src/db');
  if (!/^test_[a-z0-9_]+$/.test(db.name) || db.name !== process.env.MONGODB_DATABASE) throw new Error('Test cleanup refused: expected this process\'s isolated MongoDB database');
  try { await db.drop(); }
  finally { await db.close(); }
}
