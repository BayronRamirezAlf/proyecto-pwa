import pg from 'pg';

/** Interfaz mínima común a `pg.Pool` y a PGlite (pruebas), para no acoplar los repositorios. */
export interface Db {
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<{ rows: T[] }>;
  /** Ejecuta un script con varias sentencias (migraciones). */
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}

export function createPgDb(connectionString: string): Db {
  const pool = new pg.Pool({ connectionString, max: 10, idleTimeoutMillis: 30_000 });
  return {
    async query<T>(text: string, params?: unknown[]) {
      const res = await pool.query(text, params);
      return { rows: res.rows as T[] };
    },
    async exec(sql: string) {
      // Misma conexión para el script y su ROLLBACK: si falla a media transacción,
      // la conexión no regresa al pool en estado "aborted".
      const client = await pool.connect();
      try {
        await client.query(sql);
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
    async close() {
      await pool.end();
    },
  };
}
