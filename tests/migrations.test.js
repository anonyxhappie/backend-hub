import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  createDb,
  applyMigrations,
  applySeed,
  listMigrationFiles,
  withDbContext,
  exportLogicalBackup,
  restoreLogicalBackup
} from '../server/db.js';

test('fresh install applies ordered migrations cleanly and is idempotent', async () => {
  const db = await createDb();
  try {
    const first = await applyMigrations(db);
    assert.equal(first.total, 5);
    assert.equal(first.newlyApplied.length, 5);
    assert.deepEqual(first.newlyApplied, [
      '0001_core_extensions_and_auth_helpers.sql',
      '0002_apps_and_memberships.sql',
      '0003_profiles_and_records.sql',
      '0004_storage_and_quotas.sql',
      '0005_audit_and_views.sql'
    ]);

    const second = await applyMigrations(db);
    assert.equal(second.newlyApplied.length, 0);
  } finally {
    await db.close();
  }
});

test('incremental upgrade from prior schema and rejection of tampered/stale migrations', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'bh-mig-'));
  const db = await createDb();
  try {
    const realFiles = await listMigrationFiles();
    for (const f of realFiles.slice(0, 3)) {
      await fs.copyFile(path.resolve('supabase/migrations', f), path.join(tmpDir, f));
    }

    const step1 = await applyMigrations(db, { migrationsDir: tmpDir });
    assert.equal(step1.newlyApplied.length, 3);

    // Insert representative prior-schema data before applying 0004 & 0005
    await withDbContext(db, { role: 'service_role', claims: { role: 'service_role' } }, async (tx) => {
      const u = await tx.query(
        `INSERT INTO auth.users (email, password_hash) VALUES ('upgrade@example.com', 'hash') RETURNING id`
      );
      await tx.query(`INSERT INTO public.apps (id, name) VALUES ('upgrade-app', 'Upgrade App')`);
      await tx.query(`INSERT INTO public.app_memberships (app_id, user_id, role) VALUES ('upgrade-app', $1, 'member')`, [
        u.rows[0].id
      ]);
      await tx.query(
        `INSERT INTO public.app_records (app_id, owner_id, collection, title) VALUES ('upgrade-app', $1, 'notes', 'Before upgrade')`,
        [u.rows[0].id]
      );
    });

    // Apply remaining migrations 0004 and 0005
    for (const f of realFiles.slice(3)) {
      await fs.copyFile(path.resolve('supabase/migrations', f), path.join(tmpDir, f));
    }
    const step2 = await applyMigrations(db, { migrationsDir: tmpDir });
    assert.equal(step2.newlyApplied.length, 2);

    // Verify existing data survived and reconcile_app_usage works on upgraded DB
    const rec = await db.query("SELECT * FROM hub_private.reconcile_app_usage('upgrade-app')");
    assert.equal(rec.rows[0].record_count, 1);

    // Tamper with an already-applied migration -> must fail closed
    await fs.appendFile(path.join(tmpDir, realFiles[0]), '\n-- tampered\n');
    await assert.rejects(() => applyMigrations(db, { migrationsDir: tmpDir }), /checksum mismatch/i);

    // Restore file and attempt out-of-order stale migration -> must reject
    await fs.copyFile(path.resolve('supabase/migrations', realFiles[0]), path.join(tmpDir, realFiles[0]));
    await fs.writeFile(path.join(tmpDir, '0002_stale_backfill.sql'), 'SELECT 1;');
    await assert.rejects(() => applyMigrations(db, { migrationsDir: tmpDir }), /out-of-order/i);
  } finally {
    await db.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('backup export and restore drill onto clean database preserves data and usage invariants', async () => {
  const sourceDb = await createDb();
  const targetDb = await createDb();
  try {
    await applyMigrations(sourceDb);
    await applySeed(sourceDb);

    await withDbContext(sourceDb, { role: 'service_role', claims: { role: 'service_role' } }, async (tx) => {
      const u = await tx.query(
        `INSERT INTO auth.users (email, password_hash) VALUES ('drill@example.com', 'hash') RETURNING id`
      );
      const userId = u.rows[0].id;
      await tx.query(`INSERT INTO public.app_memberships (app_id, user_id, role) VALUES ('notes-demo', $1, 'member')`, [
        userId
      ]);
      await tx.query(
        `INSERT INTO public.app_records (app_id, owner_id, collection, visibility, title, payload)
         VALUES ('notes-demo', $1, 'notes', 'private', 'Drill Note', '{"ok":true}'::jsonb)`,
        [userId]
      );
      await tx.query("SELECT * FROM hub_private.reconcile_app_usage('notes-demo')");
    });

    const snapshot = await exportLogicalBackup(sourceDb);
    await applyMigrations(targetDb);
    await restoreLogicalBackup(targetDb, snapshot);

    const restoredRecords = await targetDb.query('SELECT title, app_id FROM public.app_records');
    assert.equal(restoredRecords.rows.length, 1);
    assert.equal(restoredRecords.rows[0].title, 'Drill Note');

    const reconciled = await targetDb.query("SELECT * FROM hub_private.reconcile_app_usage('notes-demo')");
    assert.equal(reconciled.rows[0].record_count, 1);
  } finally {
    await sourceDb.close();
    await targetDb.close();
  }
});
