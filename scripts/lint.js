import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

async function walk(dir, exts) {
  const out = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === '.local-hub') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await walk(full, exts)));
    } else if (exts.some((ext) => e.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

async function main() {
  const jsFiles = await walk(ROOT, ['.js', '.mjs']);
  for (const file of jsFiles) {
    execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  }

  // Ensure client bundles and example apps contain zero privileged server credentials
  const clientFiles = [
    ...(await walk(path.join(ROOT, 'packages', 'sdk'), ['.js', '.mjs'])),
    ...(await walk(path.join(ROOT, 'examples'), ['.js', '.mjs', '.html'])),
  ];
  const forbiddenPatterns = [
    /HUB_SERVICE_ROLE_KEY/,
    /HUB_JWT_SECRET/,
    /SUPABASE_SERVICE_ROLE_KEY/,
    /local-dev-only-/,
  ];
  for (const file of clientFiles) {
    const content = await fs.readFile(file, 'utf8');
    for (const pat of forbiddenPatterns) {
      if (pat.test(content)) {
        throw new Error(`Forbidden privileged credential/secret reference (${pat}) found in client file: ${file}`);
      }
    }
  }

  // Validate ordered migrations and ensure every public table enables + forces RLS
  const migDir = path.join(ROOT, 'supabase', 'migrations');
  const migFiles = (await fs.readdir(migDir)).filter((f) => f.endsWith('.sql')).sort();
  let allSql = '';
  for (let i = 0; i < migFiles.length; i++) {
    const expectedPrefix = String(i + 1).padStart(4, '0') + '_';
    if (!migFiles[i].startsWith(expectedPrefix)) {
      throw new Error(`Migration ordering mismatch: expected prefix ${expectedPrefix}, got ${migFiles[i]}`);
    }
    allSql += '\n' + (await fs.readFile(path.join(migDir, migFiles[i]), 'utf8'));
  }

  const createdTables = [...allSql.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?public\.([a-z0-9_]+)/gi)].map(
    (m) => m[1]
  );
  for (const tbl of createdTables) {
    const enableRe = new RegExp(`ALTER TABLE\\s+public\\.${tbl}\\s+ENABLE ROW LEVEL SECURITY`, 'i');
    const forceRe = new RegExp(`ALTER TABLE\\s+public\\.${tbl}\\s+FORCE ROW LEVEL SECURITY`, 'i');
    if (!enableRe.test(allSql) || !forceRe.test(allSql)) {
      throw new Error(`Public table public.${tbl} is missing ENABLE/FORCE ROW LEVEL SECURITY in migrations`);
    }
  }

  console.log(`Lint passed: ${jsFiles.length} JS/MJS files syntax-checked, ${migFiles.length} migrations validated, ${createdTables.length} public tables verified for RLS.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
