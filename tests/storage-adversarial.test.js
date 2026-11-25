import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestHarness } from './helpers/harness.js';
import { withDbContext } from '../server/db.js';
import { signJwt } from '../server/crypto.js';

test('storage policies: private buckets, path traversal rejection, cross-user isolation, and MIME/size checks', async () => {
  const h = await createTestHarness();
  try {
    const alice = await h.createUser('stor-alice@example.com');
    const bob = await h.createUser('stor-bob@example.com');
    await h.addMembership('notes-demo', alice.user.id, 'member');
    await h.addMembership('notes-demo', bob.user.id, 'member');

    const aliceCtx = (await h.issueAppCtx('notes-demo', alice.token)).data.appContextToken;
    const bobCtx = (await h.issueAppCtx('notes-demo', bob.token)).data.appContextToken;

    // 1. Public bucket creation is blocked by DB constraint
    await assert.rejects(
      () =>
        withDbContext(h.db, { role: 'service_role', claims: { role: 'service_role' } }, (tx) =>
          tx.query(`INSERT INTO public.storage_buckets (id, app_id, is_public) VALUES ('bad-public', 'notes-demo', true)`)
        ),
      /check constraint/i
    );

    // 2. Direct client INSERT/UPDATE/DELETE into storage_objects is blocked
    await assert.rejects(
      () =>
        withDbContext(
          h.db,
          {
            role: 'authenticated',
            claims: {
              sub: alice.user.id,
              role: 'authenticated',
              app_id: 'notes-demo',
              app_caps: ['storage:write'],
              app_ctx_verified: 'true',
              app_ctx_exp: Math.floor(Date.now() / 1000) + 300,
            },
          },
          (tx) =>
            tx.query(
              `INSERT INTO public.storage_objects (bucket_id, app_id, owner_id, relative_path, object_path, mime_type, size_bytes, status)
               VALUES ('notes-files', 'notes-demo', $1, 'a.txt', $2, 'text/plain', 10, 'active')`,
              [alice.user.id, `notes-demo/${alice.user.id}/a.txt`]
            )
        ),
      /permission denied/i
    );

    // 3. Path traversal / bad path segments rejected
    for (const badPath of ['../secret.txt', '/abs.txt', 'a//b.txt', 'a\\b.txt', 'a%2fb.txt', '.', '..']) {
      const badIntent = await h.api('/functions/v1/storage-upload-intent', {
        method: 'POST',
        token: alice.token,
        appCtx: aliceCtx,
        body: { bucketId: 'notes-files', relativePath: badPath, mimeType: 'text/plain', sizeBytes: 10 },
      });
      assert.equal(badIntent.status, 400, `Path "${badPath}" must be rejected`);
    }

    // 4. Cross-app bucket access rejected
    const wrongBucket = await h.api('/functions/v1/storage-upload-intent', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      body: { bucketId: 'habits-files', relativePath: 'ok.txt', mimeType: 'text/plain', sizeBytes: 10 },
    });
    assert.equal(wrongBucket.status, 403);

    // 5. MIME mismatch rejected on binary upload (fake PNG bytes)
    const fakePngPayload = Buffer.from('<script>alert(1)</script>');
    const pngIntent = await h.api('/functions/v1/storage-upload-intent', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      body: { bucketId: 'notes-files', relativePath: 'fake.png', mimeType: 'image/png', sizeBytes: fakePngPayload.length },
    });
    assert.equal(pngIntent.status, 201);
    const badPngUpload = await h.api(`/storage/v1/object/upload?token=${encodeURIComponent(pngIntent.data.uploadToken)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'image/png' },
      body: fakePngPayload,
    });
    assert.equal(badPngUpload.status, 415);

    // 6. Valid upload -> signed download URL -> cross-user access denied -> expired signed URL denied
    const payload = Buffer.from('hello private storage');
    const intent = await h.api('/functions/v1/storage-upload-intent', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      body: { bucketId: 'notes-files', relativePath: 'docs/hello.txt', mimeType: 'text/plain', sizeBytes: payload.length },
    });
    assert.equal(intent.status, 201);
    assert.equal(intent.data.objectPath, `notes-demo/${alice.user.id}/docs/hello.txt`);

    // Attempting to upload MORE bytes than reserved fails closed
    const oversizeUpload = await h.api(`/storage/v1/object/upload?token=${encodeURIComponent(intent.data.uploadToken)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: Buffer.concat([payload, Buffer.from('extra-bytes')]),
    });
    assert.equal(oversizeUpload.status, 413);

    // Exact reserved size succeeds
    const commitRes = await h.api(`/storage/v1/object/upload?token=${encodeURIComponent(intent.data.uploadToken)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: payload,
    });
    assert.equal(commitRes.status, 200);
    const obj = commitRes.data.object;
    assert.equal(obj.status, 'active');

    // Bob cannot list, sign, or delete Alice's private file
    const bobList = await h.api('/rest/v1/storage_objects', { token: bob.token, appCtx: bobCtx });
    assert.deepEqual(bobList.data, []);

    const bobSign = await h.api('/functions/v1/storage-signed-url', {
      method: 'POST',
      token: bob.token,
      appCtx: bobCtx,
      body: { objectId: obj.id },
    });
    assert.equal(bobSign.status, 404);

    const bobDel = await h.api(`/functions/v1/storage-object?objectId=${obj.id}`, {
      method: 'DELETE',
      token: bob.token,
      appCtx: bobCtx,
    });
    assert.equal(bobDel.status, 404);

    // Alice gets signed URL and downloads bytes with nosniff + CSP headers
    const signRes = await h.api('/functions/v1/storage-signed-url', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      body: { objectId: obj.id, expiresInSeconds: 60 },
    });
    assert.equal(signRes.status, 200);

    const dlRes = await h.api(signRes.data.signedUrl);
    assert.equal(dlRes.status, 200);
    assert.equal(Buffer.from(dlRes.data).toString('utf8'), 'hello private storage');
    assert.equal(dlRes.headers.get('x-content-type-options'), 'nosniff');

    // Expired signed URL fails
    const expiredDlToken = signJwt(
      { object_id: obj.id, bucket_id: obj.bucket_id, app_id: obj.app_id, owner_id: obj.owner_id, object_path: obj.object_path },
      h.downloadSecret,
      { audience: 'backend-hub:storage-download', ttlSeconds: -5 }
    );
    const expiredDl = await h.api(`/storage/v1/object/sign?token=${encodeURIComponent(expiredDlToken)}`);
    assert.equal(expiredDl.status, 403);

    // 7. Cross-tenant/path move blocked by storage_objects immutability trigger
    await assert.rejects(
      () =>
        withDbContext(h.db, { role: 'service_role', claims: { role: 'service_role' } }, (tx) =>
          tx.query(`UPDATE public.storage_objects SET app_id = 'habits-demo' WHERE id = $1`, [obj.id])
        ),
      /IMMUTABLE_STORAGE_PATH/i
    );
  } finally {
    await h.cleanup();
  }
});

test('concurrent storage quota reservations, idempotency, and server-side reconciliation', async () => {
  const h = await createTestHarness();
  try {
    // Tighten user quota on notes-demo to 1000 bytes
    await h.db.query(`UPDATE public.apps SET max_user_storage_bytes = 1000, max_storage_bytes = 5000 WHERE id = 'notes-demo'`);

    const alice = await h.createUser('quota-alice@example.com');
    await h.addMembership('notes-demo', alice.user.id, 'member');
    const aliceCtx = (await h.issueAppCtx('notes-demo', alice.token)).data.appContextToken;

    // 1. Idempotency: repeated intent with same Idempotency-Key reuses single reservation
    const idem1 = await h.api('/functions/v1/storage-upload-intent', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      headers: { 'Idempotency-Key': 'same-key-1' },
      body: { bucketId: 'notes-files', relativePath: 'idem.txt', mimeType: 'text/plain', sizeBytes: 400 },
    });
    const idem2 = await h.api('/functions/v1/storage-upload-intent', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      headers: { 'Idempotency-Key': 'same-key-1' },
      body: { bucketId: 'notes-files', relativePath: 'idem.txt', mimeType: 'text/plain', sizeBytes: 400 },
    });
    assert.equal(idem1.status, 201);
    assert.equal(idem2.status, 201);
    assert.equal(idem2.data.reservationId, idem1.data.reservationId);
    assert.equal(idem2.data.reused, true);

    // 2. Fire 5 parallel 400-byte reservations (already 400 reserved -> at most 1 more fits within 1000 bytes!)
    const parallelResults = await Promise.all(
      [1, 2, 3, 4, 5].map((n) =>
        h.api('/functions/v1/storage-upload-intent', {
          method: 'POST',
          token: alice.token,
          appCtx: aliceCtx,
          body: { bucketId: 'notes-files', relativePath: `race-${n}.txt`, mimeType: 'text/plain', sizeBytes: 400 },
        })
      )
    );

    const successes = parallelResults.filter((r) => r.status === 201);
    const quotaDenied = parallelResults.filter((r) => r.status === 429 && r.data.error.code === 'QUOTA_EXCEEDED');
    assert.equal(successes.length, 1, 'Exactly one more 400B reservation fits inside 1000B limit');
    assert.equal(quotaDenied.length, 4, 'Remaining 4 concurrent attempts must hit QUOTA_EXCEEDED');

    // 3. Expire reservations and run quota-reconcile
    await h.db.query(`UPDATE public.quota_reservations SET expires_at = now() - interval '1 minute' WHERE status = 'reserved'`);

    // Unprivileged member cannot invoke quota-reconcile
    const memberReconcile = await h.api('/functions/v1/quota-reconcile', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceCtx,
      body: { appId: 'notes-demo' },
    });
    assert.equal(memberReconcile.status, 403);

    // Service role reconciles and reclaims expired bytes
    const svcReconcile = await h.api('/functions/v1/quota-reconcile', {
      method: 'POST',
      headers: { 'x-service-role-key': h.config.serviceRoleKey },
      body: { appId: 'notes-demo' },
    });
    assert.equal(svcReconcile.status, 200);
    assert.equal(svcReconcile.data.reconciled[0].reserved_storage_bytes, 0);
    assert.equal(svcReconcile.data.reconciled[0].expired_reservations, 2);
  } finally {
    await h.cleanup();
  }
});
