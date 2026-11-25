#!/usr/bin/env node
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import {
  createDb,
  applyMigrations,
  applySeed,
  withDbContext,
  exportLogicalBackup,
  restoreLogicalBackup,
} from './db.js';
import { PrivateStorageStore } from './storage-store.js';
import { startHubServer, validateServerConfig } from './app.js';

const MIME_MAP = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function resolveRuntimeConfig(envVars) {
  const hubEnv = envVars.HUB_ENV || 'local';
  if (hubEnv !== 'local' && (!envVars.HUB_JWT_SECRET || !envVars.HUB_SERVICE_ROLE_KEY)) {
    throw new Error(`HUB_ENV=${hubEnv} requires explicit HUB_JWT_SECRET and HUB_SERVICE_ROLE_KEY.`);
  }
  return validateServerConfig({
    environment: hubEnv,
    jwtSecret: envVars.HUB_JWT_SECRET || 'local-dev-only-jwt-secret-change-me-32chars',
    serviceRoleKey: envVars.HUB_SERVICE_ROLE_KEY || 'local-dev-only-service-key-change-me-32chars',
  });
}

function startStaticAppServer({ rootDir, sdkDistDir, portfolioCfgPath, port, host = '127.0.0.1' }) {
  const absRoot = path.resolve(rootDir);
  const absSdk = path.resolve(sdkDistDir);
  const absPortfolio = path.resolve(portfolioCfgPath);

  const server = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url || '/', `http://${host}:${port}`);
    let filePath;
    if (reqUrl.pathname.startsWith('/sdk/')) {
      const rel = reqUrl.pathname.slice('/sdk/'.length);
      filePath = path.resolve(absSdk, rel);
      if (!filePath.startsWith(absSdk + path.sep)) {
        res.statusCode = 403;
        return res.end('Forbidden');
      }
    } else if (reqUrl.pathname === '/portfolio-config.js') {
      filePath = absPortfolio;
    } else {
      const rel = reqUrl.pathname === '/' ? 'index.html' : reqUrl.pathname.replace(/^\/+/, '');
      filePath = path.resolve(absRoot, rel);
      if (filePath !== absRoot && !filePath.startsWith(absRoot + path.sep)) {
        res.statusCode = 403;
        return res.end('Forbidden');
      }
    }

    try {
      const data = await fs.readFile(filePath);
      const ext = path.extname(filePath);
      res.statusCode = 200;
      res.setHeader('Content-Type', MIME_MAP[ext] || 'application/octet-stream');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' http://127.0.0.1:* http://localhost:*; img-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
      );
      res.end(data);
    } catch {
      res.statusCode = 404;
      res.end('Not found');
    }
  });

  return new Promise((resolve) => {
    server.listen(port, host, () => {
      resolve({
        url: `http://${host}:${port}`,
        close: () =>
          new Promise((r) => {
            server.closeAllConnections?.();
            server.close(r);
          }),
      });
    });
  });
}

async function main() {
  const cmd = process.argv[2] || 'serve';
  const dataDir = process.env.HUB_DATA_DIR || path.resolve(process.cwd(), '.local-hub/pgdata');
  const storageDir = process.env.HUB_STORAGE_DIR || path.resolve(process.cwd(), '.local-hub/storage');
  await fs.mkdir(dataDir, { recursive: true });

  const db = await createDb({ dataDir });
  const storage = new PrivateStorageStore(storageDir);
  await storage.init();

  if (cmd === 'migrate') {
    const res = await applyMigrations(db);
    console.log(JSON.stringify({ ok: true, ...res }));
    await db.close();
    return;
  }

  if (cmd === 'seed') {
    if ((process.env.HUB_ENV || 'local') === 'production') {
      throw new Error('Refusing to seed when HUB_ENV=production');
    }
    await applyMigrations(db);
    await applySeed(db);
    console.log(JSON.stringify({ ok: true, seeded: true }));
    await db.close();
    return;
  }

  if (cmd === 'reconcile') {
    await applyMigrations(db);
    const rows = await withDbContext(db, { role: 'service_role', claims: { role: 'service_role' } }, async (tx) => {
      const r = await tx.query('SELECT * FROM hub_private.reconcile_app_usage(NULL)');
      return r.rows;
    });
    console.log(JSON.stringify({ ok: true, reconciled: rows }, null, 2));
    await db.close();
    return;
  }

  if (cmd === 'export' || cmd === 'backup') {
    const outFile = process.argv[3] || path.resolve(process.cwd(), '.local-hub/backup.json');
    await applyMigrations(db);
    const backup = await exportLogicalBackup(db);
    await fs.writeFile(outFile, JSON.stringify(backup, null, 2), 'utf8');
    console.log(JSON.stringify({ ok: true, outFile, exportedAt: backup.exportedAt }));
    await db.close();
    return;
  }

  if (cmd === 'restore') {
    const inFile = process.argv[3];
    if (!inFile) throw new Error('Usage: node server/cli.js restore <backup.json>');
    await applyMigrations(db);
    const raw = await fs.readFile(inFile, 'utf8');
    await restoreLogicalBackup(db, JSON.parse(raw));
    console.log(JSON.stringify({ ok: true, restoredFrom: inFile }));
    await db.close();
    return;
  }

  if (cmd === 'serve') {
    if (!process.env.HUB_ENV) {
      process.env.HUB_ENV = 'local';
    }
    const config = resolveRuntimeConfig(process.env);
    const migRes = await applyMigrations(db);
    config.migrationsApplied = migRes.total;
    if (config.environment === 'local') {
      await applySeed(db);
    }

    const apiPort = Number(process.env.HUB_PORT || 4000);
    const notesUiPort = Number(process.env.HUB_EXAMPLE_UI_PORT || 4100);
    const habitsUiPort = Number(process.env.HUB_HABITS_UI_PORT || 4101);
    const dashboardPort = Number(process.env.HUB_DASHBOARD_PORT || 4102);

    const hub = await startHubServer({ db, storage, config, port: apiPort });
    const notesUi = await startStaticAppServer({
      rootDir: path.resolve(process.cwd(), 'examples/notes-app'),
      sdkDistDir: path.resolve(process.cwd(), 'packages/sdk/dist'),
      portfolioCfgPath: path.resolve(process.cwd(), 'examples/portfolio-config.js'),
      port: notesUiPort,
    });
    const habitsUi = await startStaticAppServer({
      rootDir: path.resolve(process.cwd(), 'examples/habits-app'),
      sdkDistDir: path.resolve(process.cwd(), 'packages/sdk/dist'),
      portfolioCfgPath: path.resolve(process.cwd(), 'examples/portfolio-config.js'),
      port: habitsUiPort,
    });
    const dashboardUi = await startStaticAppServer({
      rootDir: path.resolve(process.cwd(), 'examples/hub-dashboard'),
      sdkDistDir: path.resolve(process.cwd(), 'packages/sdk/dist'),
      portfolioCfgPath: path.resolve(process.cwd(), 'examples/portfolio-config.js'),
      port: dashboardPort,
    });

    console.log(`Backend Hub (${config.environment}) API listening at ${hub.url}`);
    console.log(`Notes Demo UI (notes-demo) listening at ${notesUi.url}`);
    console.log(`Habits Demo UI (habits-demo) listening at ${habitsUi.url}`);
    console.log(`Portfolio Dashboard listening at ${dashboardUi.url}`);

    const shutdown = async () => {
      await dashboardUi.close();
      await habitsUi.close();
      await notesUi.close();
      await hub.close();
      await db.close();
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  throw new Error(`Unknown command: ${cmd}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
