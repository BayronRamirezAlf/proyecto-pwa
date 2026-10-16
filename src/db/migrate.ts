import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPgDb, type Db } from './db.ts';

const MIGRATIONS_DIR = fileURLToPath(new URL('../../db/migrations/', import.meta.url));
const NAME = /^\d{3}_[a-z0-9_]+\.sql$/;

/** Aplica en orden las migraciones pendientes de db/migrations, cada una en su transacción. */
export async function runMigrations(db: Db, dir = MIGRATIONS_DIR): Promise<string[]> {
  await db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(100) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
  const { rows } = await db.query<{ version: string }>('SELECT version FROM schema_migrations');
  const applied = new Set(rows.map((r) => r.version));
  const files = (await readdir(dir)).filter((f) => NAME.test(f)).sort();

  const newlyApplied: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await readFile(join(dir, file), 'utf8');
    try {
      // `file` ya pasó por NAME, así que es seguro interpolarlo.
      await db.exec(`BEGIN;\n${sql}\n;\nINSERT INTO schema_migrations (version) VALUES ('${file}');\nCOMMIT;`);
    } catch (e) {
      await db.exec('ROLLBACK').catch(() => {});
      throw new Error(`Falló la migración ${file}: ${(e as Error).message}`);
    }
    newlyApplied.push(file);
  }
  return newlyApplied;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('DATABASE_URL no está definido');
    process.exit(1);
  }
  const db = createPgDb(url);
  try {
    const done = await runMigrations(db);
    console.log(done.length ? `Migraciones aplicadas: ${done.join(', ')}` : 'Sin migraciones pendientes');
  } finally {
    await db.close();
  }
}
