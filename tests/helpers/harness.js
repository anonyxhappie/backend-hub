import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createDb, applyMigrations, applySeed, withDbContext } from '../../server/db.js';
import { deriveSubkey } from '../../server/crypto.js';
import { PrivateStorageStore } from '../../server/storage-store.js';
import { startHubServer } from '../../server/app.js';

export const TEST_CONFIG = {
  environment: 'local',
  jwtSecret: 'test-only-master-jwt-secret-min-32-chars!!',
  serviceRoleKey: 'test-only-service-role-key-32-chars!!',
  appCtxTtlSeconds: 300,
  userJwtTtlSeconds: 900,
  migrationsApplied: 5,
};

export async function createTestHarness({ seed = true, configOverrides = {} } = {}) {
  const db = await createDb();
  await applyMigrations(db);
  if (seed) {
    await applySeed(db);
  }
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'backend-hub-test-'));
  const storage = new PrivateStorageStore(tmpDir);
  await storage.init();

  const config = { ...TEST_CONFIG, ...configOverrides };
  const server = await startHubServer({ db, storage, config, port: 0 });
  const appCtxSecret = deriveSubkey(config.jwtSecret, 'app-context');
  const downloadSecret = deriveSubkey(config.jwtSecret, 'storage-download');

  async function api(route, { method = 'GET', token = null, appCtx = null, headers = {}, body = undefined } = {}) {
    const reqHeaders = {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(appCtx ? { 'x-app-context': appCtx } : {}),
      ...headers,
    };
    let rawBody = body;
    if (body !== undefined && !(body instanceof Uint8Array) && typeof body !== 'string') {
      reqHeaders['Content-Type'] = 'application/json';
      rawBody = JSON.stringify(body);
    }
    const resp = await fetch(`${server.url}${route}`, {
      method,
      headers: reqHeaders,
      body: rawBody,
    });
    const ct = resp.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await resp.json() : await resp.arrayBuffer();
    return { status: resp.status, headers: resp.headers, data };
  }

  async function createUser(email, password = 'StrongPassword123!') {
    const res = await api('/auth/v1/signup', {
      method: 'POST',
      body: { email, password },
    });
    if (res.status !== 201) {
      throw new Error(`Signup failed for ${email}: ${JSON.stringify(res.data)}`);
    }
    return { token: res.data.accessToken, user: res.data.user };
  }

  async function addMembership(appId, userId, role = 'member', status = 'active') {
    await withDbContext(db, { role: 'service_role', claims: { role: 'service_role' } }, async (tx) => {
      await tx.query(
        `INSERT INTO public.app_memberships (app_id, user_id, role, status)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (app_id, user_id) DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status`,
        [appId, userId, role, status]
      );
    });
  }

  async function issueAppCtx(appId, token = null, origin = null) {
    const headers = origin ? { Origin: origin } : {};
    return api('/functions/v1/issue-app-context', {
      method: 'POST',
      token,
      headers,
      body: { appId },
    });
  }

  async function cleanup() {
    await server.close();
    await db.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  }

  return {
    db,
    storage,
    server,
    url: server.url,
    config,
    appCtxSecret,
    downloadSecret,
    api,
    createUser,
    addMembership,
    issueAppCtx,
    cleanup,
  };
}
