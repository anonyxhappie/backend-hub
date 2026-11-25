import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createTestHarness } from './helpers/harness.js';
import { createHubClient, SDK_VERSION } from '../packages/sdk/src/index.js';
import { ConfigError, QuotaError, TimeoutError } from '../packages/sdk/src/errors.js';
import { resolveAppConfig, PINNED_SDK_VERSION } from '../examples/portfolio-config.js';

test('SDK fails closed on invalid or missing environment configuration and pins immutable version', async () => {
  assert.equal(SDK_VERSION, '0.1.0');

  // Missing environment
  assert.throws(() => createHubClient({ baseUrl: 'http://127.0.0.1:4000', appId: 'notes-demo' }), ConfigError);
  // Missing baseUrl (no silent production fallback!)
  assert.throws(() => createHubClient({ environment: 'production', appId: 'notes-demo' }), ConfigError);
  // Production refuses insecure http://
  assert.throws(
    () => createHubClient({ environment: 'production', baseUrl: 'http://example.com', appId: 'notes-demo' }),
    ConfigError
  );
  // Refuses privileged credentials in client config
  assert.throws(
    () =>
      createHubClient({
        environment: 'local',
        baseUrl: 'http://127.0.0.1:4000',
        appId: 'notes-demo',
        serviceRoleKey: 'secret',
      }),
    ConfigError
  );

  // Built immutable bundle exists and matches package.json version; example app pins exact version
  const pkg = JSON.parse(await fs.readFile(path.resolve('packages/sdk/package.json'), 'utf8'));
  const bundlePath = path.resolve(`packages/sdk/dist/backend-hub-sdk-${pkg.version}.mjs`);
  await fs.access(bundlePath);

  const exampleAppSrc = await fs.readFile(path.resolve('examples/notes-app/app.js'), 'utf8');
  const importMatch = exampleAppSrc.match(/import\s+\{[^}]+\}\s+from\s+['"]([^'"]+)['"]/);
  assert.ok(importMatch, 'Example app must import the pinned SDK bundle');
  assert.equal(importMatch[1], `/sdk/backend-hub-sdk-${pkg.version}.mjs`);
  assert.ok(!importMatch[1].includes('latest') && !importMatch[1].includes('/main/'));
});

test('SDK timeout and safe idempotent retry behavior', async () => {
  let getCalls = 0;
  let postCalls = 0;

  const mockFetch = async (_url, init) => {
    if (init.method === 'GET') {
      getCalls++;
      if (getCalls === 1) {
        return new Response(JSON.stringify({ error: { code: 'BAD_GATEWAY', message: 'transient' } }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    postCalls++;
    return new Response(JSON.stringify({ error: { code: 'BAD_GATEWAY', message: 'transient' } }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  const client = createHubClient({
    environment: 'local',
    baseUrl: 'http://127.0.0.1:4000',
    appId: 'notes-demo',
    maxRetries: 2,
    fetchImpl: mockFetch,
  });

  const health = await client.health();
  assert.equal(health.ok, true);
  assert.equal(getCalls, 2, 'Idempotent GET retries once after transient 503');

  await assert.rejects(() => client.auth.login('a@b.com', 'password123'), /transient/);
  assert.equal(postCalls, 1, 'Non-idempotent POST login must NOT retry on 503');

  // Timeout test
  const slowFetch = (_url, init) =>
    new Promise((_, reject) => {
      init.signal.addEventListener('abort', () => {
        const e = new Error('Aborted');
        e.name = 'AbortError';
        reject(e);
      });
    });

  const slowClient = createHubClient({
    environment: 'local',
    baseUrl: 'http://127.0.0.1:4000',
    appId: 'notes-demo',
    timeoutMs: 30,
    maxRetries: 0,
    fetchImpl: slowFetch,
  });
  await assert.rejects(() => slowClient.health(), TimeoutError);
});

test('end-to-end SDK flow: signup, enroll, profile, notes CRUD, private storage, trusted function, and quota error', async () => {
  const h = await createTestHarness();
  try {
    const client = createHubClient({
      environment: 'local',
      baseUrl: h.url,
      appId: 'notes-demo',
    });

    const health = await client.health();
    assert.equal(health.ok, true);
    assert.equal(health.db, 'ok');

    // Signup + self-enroll
    const user = await client.auth.signup('e2e@example.com', 'VeryStrongPass123!');
    assert.equal(user.email, 'e2e@example.com');
    const membership = await client.app.enroll();
    assert.equal(membership.role, 'member');

    // Profile upsert + read
    const prof = await client.profile.upsert({ displayName: 'E2E User', bio: 'Testing Backend Hub' });
    assert.equal(prof.display_name, 'E2E User');
    const fetchedProf = await client.profile.get();
    assert.equal(fetchedProf.bio, 'Testing Backend Hub');

    // Notes CRUD
    const created = await client.db('notes').create({
      title: 'SDK Note',
      visibility: 'private',
      payload: { body: 'Hello from SDK' },
    });
    assert.equal(created.title, 'SDK Note');

    const updated = await client.db('notes').update(created.id, { title: 'SDK Note v2' });
    assert.equal(updated.title, 'SDK Note v2');

    const list = await client.db('notes').list();
    assert.equal(list.length, 1);

    // Private storage upload -> signed download -> delete
    const uploaded = await client.storage.upload('notes-files', 'folder/readme.txt', 'private-file-content', {
      mimeType: 'text/plain',
    });
    assert.equal(uploaded.status, 'active');

    const signed = await client.storage.createSignedUrl(uploaded.id, { expiresInSeconds: 60 });
    const dlResp = await fetch(signed.url);
    assert.equal(dlResp.status, 200);
    assert.equal(await dlResp.text(), 'private-file-content');

    // Trusted server function
    const summary = await client.functions.invoke('trusted-note-summary');
    assert.equal(summary.appId, 'notes-demo');
    assert.equal(summary.storageStats.file_count, 1);

    // Typed QuotaError surfaced when exceeding upload limit
    await assert.rejects(
      () =>
        client.storage.upload('notes-files', 'folder/too-big.txt', new Uint8Array(2_000_000), {
          mimeType: 'text/plain',
        }),
      QuotaError
    );

    // Cleanup
    await client.storage.remove(uploaded.id);
    await client.db('notes').remove(created.id);
    assert.deepEqual(await client.db('notes').list(), []);
  } finally {
    await h.cleanup();
  }
});

test('example apps HTML IDs match app.js and portfolio-config fails closed on unconfigured environments', async () => {
  for (const appDir of ['notes-app', 'habits-app', 'hub-dashboard']) {
    const html = await fs.readFile(path.resolve(`examples/${appDir}/index.html`), 'utf8');
    const appJs = await fs.readFile(path.resolve(`examples/${appDir}/app.js`), 'utf8');

    const referencedIds = [...new Set([...appJs.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]))];
    assert.ok(referencedIds.length >= 6, `Expected DOM element IDs in examples/${appDir}/app.js`);
    for (const id of referencedIds) {
      assert.ok(html.includes(`id="${id}"`), `examples/${appDir}/index.html is missing id="${id}"`);
    }
    const importMatch = appJs.match(/import\s+\{[^}]+\}\s+from\s+['"]([^'"]+)['"]/);
    assert.equal(importMatch?.[1], `/sdk/backend-hub-sdk-${SDK_VERSION}.mjs`);
  }

  assert.equal(PINNED_SDK_VERSION, SDK_VERSION);
  assert.deepEqual(resolveAppConfig({ appId: 'habits-demo', environment: 'local' }), {
    environment: 'local',
    baseUrl: 'http://127.0.0.1:4000',
    appId: 'habits-demo',
  });
  assert.throws(() => resolveAppConfig({ appId: 'notes-demo', environment: 'staging' }), /Failing closed/i);
  assert.throws(() => resolveAppConfig({ appId: 'notes-demo', environment: 'production' }), /Failing closed/i);
  assert.throws(() => resolveAppConfig({ appId: 'notes-demo', environment: 'unknown' }), /Failing closed/i);
});
