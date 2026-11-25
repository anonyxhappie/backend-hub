import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';

const DEFAULT_MIGRATIONS_DIR = path.resolve(process.cwd(), 'supabase/migrations');

export async function createDb({ dataDir = null } = {}) {
  const pg = dataDir ? new PGlite(dataDir) : new PGlite();
  await pg.waitReady;
  return pg;
}

export async function listMigrationFiles(migrationsDir = DEFAULT_MIGRATIONS_DIR) {
  const entries = await fs.readdir(migrationsDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.sql'))
    .map((entry) => entry.name)
    .sort();
}

export async function applyMigrations(pg, { migrationsDir = DEFAULT_MIGRATIONS_DIR } = {}) {
  await pg.exec(`
    CREATE SCHEMA IF NOT EXISTS hub_private;
    CREATE TABLE IF NOT EXISTS hub_private.schema_migrations (
      version text PRIMARY KEY,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  const files = await listMigrationFiles(migrationsDir);
  if (files.length === 0) {
    throw new Error(`No migration files found in ${migrationsDir}`);
  }

  const appliedRes = await pg.query('SELECT version, checksum FROM hub_private.schema_migrations ORDER BY version ASC');
  const appliedMap = new Map(appliedRes.rows.map((r) => [r.version, r.checksum]));

  // Reject out-of-order migrations: an unapplied migration cannot precede an already-applied version.
  const highestApplied = appliedRes.rows.length > 0 ? appliedRes.rows[appliedRes.rows.length - 1].version : null;

  const newlyApplied = [];
  for (const filename of files) {
    const fullPath = path.join(migrationsDir, filename);
    const sql = await fs.readFile(fullPath, 'utf8');
    const checksum = crypto.createHash('sha256').update(sql).digest('hex');

    if (appliedMap.has(filename)) {
      if (appliedMap.get(filename) !== checksum) {
        throw new Error(`Migration checksum mismatch for already-applied migration ${filename}`);
      }
      continue;
    }

    if (highestApplied && filename < highestApplied) {
      throw new Error(
        `Stale/out-of-order migration ${filename} cannot be applied before already-applied ${highestApplied}`
      );
    }

    await pg.transaction(async (tx) => {
      await tx.exec(sql);
      await tx.query('INSERT INTO hub_private.schema_migrations (version, checksum) VALUES ($1, $2)', [
        filename,
        checksum
      ]);
    });
    newlyApplied.push(filename);
  }

  return { total: files.length, newlyApplied };
}

export async function applySeed(pg, seedPath = path.resolve(process.cwd(), 'supabase/seed.sql')) {
  const sql = await fs.readFile(seedPath, 'utf8');
  await pg.exec(sql);
}

/**
 * Executes a callback inside a PostgreSQL transaction with strictly server-verified
 * role and `request.jwt.claims` set locally.
 */
export async function withDbContext(pg, { role = 'anon', claims = {} } = {}, fn) {
  if (!['anon', 'authenticated', 'service_role'].includes(role)) {
    throw new Error(`Invalid database role: ${role}`);
  }

  return pg.transaction(async (tx) => {
    await tx.exec(`SET LOCAL ROLE ${role}`);
    await tx.query("SELECT pg_catalog.set_config('request.jwt.claims', $1, true)", [JSON.stringify(claims)]);
    return fn(tx);
  });
}

/**
 * Logical JSON snapshot export/restore for local portability and recovery drills.
 * Includes auth.users (for local/standalone DBs) and all Backend Hub tables.
 */
export async function exportLogicalBackup(pg) {
  return withDbContext(pg, { role: 'service_role', claims: { role: 'service_role' } }, async (tx) => {
    const tables = [
      'auth.users',
      'public.apps',
      'public.app_memberships',
      'public.app_profiles',
      'public.app_records',
      'public.storage_buckets',
      'public.quota_reservations',
      'public.storage_objects',
      'public.app_usage',
      'public.audit_events'
    ];
    const data = {};
    for (const table of tables) {
      const res = await tx.query(`SELECT * FROM ${table}`);
      data[table] = res.rows;
    }
    return {
      format: 'backend-hub-logical-backup-v1',
      exportedAt: new Date().toISOString(),
      tables: data
    };
  });
}

export async function restoreLogicalBackup(pg, backup) {
  if (!backup || backup.format !== 'backend-hub-logical-backup-v1' || !backup.tables) {
    throw new Error('Invalid logical backup format');
  }

  const orderedTables = [
    'auth.users',
    'public.apps',
    'public.app_memberships',
    'public.app_profiles',
    'public.storage_buckets',
    'public.quota_reservations',
    'public.storage_objects',
    'public.app_records',
    'public.app_usage',
    'public.audit_events'
  ];

  await pg.transaction(async (tx) => {
    await tx.exec(`
      TRUNCATE TABLE
        public.audit_events,
        public.app_usage,
        public.storage_objects,
        public.quota_reservations,
        public.storage_buckets,
        public.app_records,
        public.app_profiles,
        public.app_memberships,
        public.apps,
        auth.users
      RESTART IDENTITY CASCADE;
    `);

    for (const table of orderedTables) {
      const rows = backup.tables[table] || [];
      for (const row of rows) {
        const cols = Object.keys(row);
        if (cols.length === 0) continue;
        const colSql = cols.map((c) => `"${c.replace(/"/g, '""')}"`).join(', ');
        const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
        const values = cols.map((c) => {
          const val = row[c];
          if (val !== null && typeof val === 'object' && !(val instanceof Date) && !Array.isArray(val)) {
            return JSON.stringify(val);
          }
          return val;
        });
        await tx.query(`INSERT INTO ${table} (${colSql}) VALUES (${placeholders})`, values);
      }
    }
  });
}
