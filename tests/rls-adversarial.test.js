import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestHarness } from './helpers/harness.js';
import { withDbContext } from '../server/db.js';
import { signJwt } from '../server/crypto.js';

test('adversarial RLS & direct API bypass tests across users, apps, roles, views, and public data', async () => {
  const h = await createTestHarness();
  try {
    const alice = await h.createUser('alice@example.com');
    const bob = await h.createUser('bob@example.com');

    // Alice is a member of BOTH notes-demo and habits-demo; Bob is ONLY a member of notes-demo.
    await h.addMembership('notes-demo', alice.user.id, 'member');
    await h.addMembership('habits-demo', alice.user.id, 'member');
    await h.addMembership('notes-demo', bob.user.id, 'member');

    const aliceNotesCtx = (await h.issueAppCtx('notes-demo', alice.token)).data.appContextToken;
    const aliceHabitsCtx = (await h.issueAppCtx('habits-demo', alice.token)).data.appContextToken;
    const bobNotesCtx = (await h.issueAppCtx('notes-demo', bob.token)).data.appContextToken;

    // 1. Bob cannot mint an app-context token for habits-demo where he has no membership
    const bobHabitsAttempt = await h.issueAppCtx('habits-demo', bob.token);
    assert.equal(bobHabitsAttempt.status, 403);
    assert.equal(bobHabitsAttempt.data.error.code, 'MEMBERSHIP_REQUIRED');

    // 2. Missing app-context fails closed even with valid user JWT (both HTTP gate and direct SQL RLS)
    const noCtxList = await h.api('/rest/v1/app_records', { token: alice.token });
    assert.equal(noCtxList.status, 403);

    const noCtxSql = await withDbContext(
      h.db,
      { role: 'authenticated', claims: { sub: alice.user.id, role: 'authenticated' } },
      (tx) => tx.query('SELECT * FROM public.app_records')
    );
    assert.deepEqual(noCtxSql.rows, []);

    // 3. Forged / mismatched app-context tokens are rejected
    const algNoneToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhIiwiYXBwX2lkIjoiaGFiaXRzLWRlbW8ifQ.';
    const forgedRes = await h.api('/rest/v1/app_records', {
      token: bob.token,
      appCtx: algNoneToken,
    });
    assert.equal(forgedRes.status, 401);

    // Bob cannot pair Alice's app-context token with Bob's user JWT
    const stolenCtxRes = await h.api('/rest/v1/app_records', {
      token: bob.token,
      appCtx: aliceHabitsCtx,
    });
    assert.equal(stolenCtxRes.status, 403);

    // Expired app-context claim is rejected even at the PostgreSQL layer
    const expiredAppCtx = signJwt(
      { sub: alice.user.id, app_id: 'notes-demo', app_role: 'member', app_caps: ['records:read'], app_ctx_verified: 'true' },
      h.appCtxSecret.toString('hex'),
      { audience: 'backend-hub:app-context', ttlSeconds: -5 }
    );
    const expiredHttp = await h.api('/rest/v1/app_records', {
      token: alice.token,
      appCtx: expiredAppCtx,
    });
    assert.equal(expiredHttp.status, 401);

    // 4. Create records in notes-demo (private, app, public) and habits-demo (public/private)
    const alicePrivate = (
      await h.api('/rest/v1/app_records', {
        method: 'POST',
        token: alice.token,
        appCtx: aliceNotesCtx,
        body: { collection: 'notes', visibility: 'private', title: 'Alice Private Note' },
      })
    ).data;

    const aliceAppNote = (
      await h.api('/rest/v1/app_records', {
        method: 'POST',
        token: alice.token,
        appCtx: aliceNotesCtx,
        body: { collection: 'notes', visibility: 'app', title: 'Alice App Shared Note' },
      })
    ).data;

    const alicePublicNote = (
      await h.api('/rest/v1/app_records', {
        method: 'POST',
        token: alice.token,
        appCtx: aliceNotesCtx,
        body: { collection: 'notes', visibility: 'public', title: 'Alice Public Note' },
      })
    ).data;

    const aliceHabit = (
      await h.api('/rest/v1/app_records', {
        method: 'POST',
        token: alice.token,
        appCtx: aliceHabitsCtx,
        body: { collection: 'habits', visibility: 'public', title: 'Alice Habit (other app)' },
      })
    ).data;
    assert.ok(alicePrivate.id && aliceAppNote.id && alicePublicNote.id && aliceHabit.id);

    // 5. Client-supplied app_id or owner_id in POST body cannot cross tenants or impersonate owner
    const spoofAppInsert = await h.api('/rest/v1/app_records', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceNotesCtx,
      body: { app_id: 'habits-demo', collection: 'habits', title: 'Cross-app write' },
    });
    assert.equal(spoofAppInsert.status, 403);

    const spoofOwnerInsert = await h.api('/rest/v1/app_records', {
      method: 'POST',
      token: bob.token,
      appCtx: bobNotesCtx,
      body: { owner_id: alice.user.id, collection: 'notes', title: 'Spoofed Owner' },
    });
    assert.equal(spoofOwnerInsert.status, 403);

    // 6. Cross-user visibility & cross-app isolation (even with ?app_id=habits-demo query parameter!)
    const bobList = await h.api('/rest/v1/app_records?app_id=eq.habits-demo', {
      token: bob.token,
      appCtx: bobNotesCtx,
    });
    assert.equal(bobList.status, 200);
    assert.deepEqual(bobList.data, [], 'Query param ?app_id=habits-demo must return 0 rows under notes-demo RLS');

    const bobNotesList = await h.api('/rest/v1/app_records', {
      token: bob.token,
      appCtx: bobNotesCtx,
    });
    const bobTitles = bobNotesList.data.map((r) => r.title);
    assert.ok(!bobTitles.includes('Alice Private Note'), 'Bob must not see Alice private note');
    assert.ok(!bobTitles.includes('Alice Habit (other app)'), 'Bob must not see habits-demo records');
    assert.ok(bobTitles.includes('Alice App Shared Note'), 'Bob can read app-visible note in notes-demo');
    assert.ok(bobTitles.includes('Alice Public Note'), 'Bob can read public note in notes-demo');

    // Bob cannot update or delete Alice's app-visible or private note
    const bobPatch = await h.api(`/rest/v1/app_records?id=eq.${aliceAppNote.id}`, {
      method: 'PATCH',
      token: bob.token,
      appCtx: bobNotesCtx,
      body: { title: 'Hacked by Bob' },
    });
    assert.equal(bobPatch.status, 404);

    const bobDelete = await h.api(`/rest/v1/app_records?id=eq.${alicePrivate.id}`, {
      method: 'DELETE',
      token: bob.token,
      appCtx: bobNotesCtx,
    });
    assert.equal(bobDelete.status, 404);

    // 7. Anonymous public-read scope: strictly app-scoped and denied when allow_public_read=false
    const anonNotesCtx = (await h.issueAppCtx('notes-demo')).data.appContextToken;
    const anonHabitsAttempt = await h.issueAppCtx('habits-demo');
    assert.equal(anonHabitsAttempt.status, 401);

    const anonRecords = await h.api('/rest/v1/app_records', { appCtx: anonNotesCtx });
    assert.equal(anonRecords.status, 200);
    assert.deepEqual(
      anonRecords.data.map((r) => r.title),
      ['Alice Public Note']
    );

    // 8. Immutable app_id and owner_id on UPDATE (even for the owner via REST)
    const ownerImmutable = await h.api(`/rest/v1/app_records?id=eq.${alicePrivate.id}`, {
      method: 'PATCH',
      token: alice.token,
      appCtx: aliceNotesCtx,
      body: { app_id: 'habits-demo', title: 'Move attempt' },
    });
    assert.equal(ownerImmutable.status, 403);

    const ownerTransfer = await h.api(`/rest/v1/app_records?id=eq.${alicePrivate.id}`, {
      method: 'PATCH',
      token: alice.token,
      appCtx: aliceNotesCtx,
      body: { owner_id: bob.user.id, title: 'Owner change attempt' },
    });
    assert.equal(ownerTransfer.status, 403);

    // Profile isolation: Bob cannot overwrite Alice's profile or move his profile to another app
    await h.api('/rest/v1/app_profiles', {
      method: 'POST',
      token: alice.token,
      appCtx: aliceNotesCtx,
      body: { display_name: 'Alice' },
    });
    const bobProfileHijack = await h.api(`/rest/v1/app_profiles?user_id=eq.${alice.user.id}`, {
      method: 'PATCH',
      token: bob.token,
      appCtx: bobNotesCtx,
      body: { display_name: 'Hijacked' },
    });
    assert.equal(bobProfileHijack.status, 200);
    assert.deepEqual(bobProfileHijack.data, []);

    const bobProfileCrossApp = await h.api('/rest/v1/app_profiles', {
      method: 'POST',
      token: bob.token,
      appCtx: bobNotesCtx,
      body: { app_id: 'habits-demo', display_name: 'CrossApp' },
    });
    assert.equal(bobProfileCrossApp.status, 403);

    // 9. Role escalation & self-enrollment abuse blocked in PostgreSQL
    const restEscalate = await h.api('/rest/v1/app_memberships', {
      method: 'PATCH',
      token: bob.token,
      appCtx: bobNotesCtx,
      body: { role: 'owner' },
    });
    assert.equal(restEscalate.status, 403);

    await assert.rejects(
      () =>
        withDbContext(
          h.db,
          {
            role: 'authenticated',
            claims: {
              sub: bob.user.id,
              role: 'authenticated',
              app_id: 'notes-demo',
              app_ctx_verified: 'true',
              app_ctx_exp: Math.floor(Date.now() / 1000) + 300,
            },
          },
          (tx) => tx.query(`UPDATE public.app_memberships SET role = 'owner' WHERE user_id = $1`, [bob.user.id])
        ),
      /permission denied/i
    );

    // Self-enroll forbidden when allow_self_enroll=false
    const badEnroll = await h.api('/functions/v1/enroll', {
      method: 'POST',
      token: bob.token,
      body: { appId: 'habits-demo' },
    });
    assert.equal(badEnroll.status, 403);

    // Suspended membership cannot reactivate itself via hub_self_enroll
    await h.addMembership('notes-demo', bob.user.id, 'member', 'suspended');
    const suspendedEnroll = await h.api('/functions/v1/enroll', {
      method: 'POST',
      token: bob.token,
      body: { appId: 'notes-demo' },
    });
    assert.equal(suspendedEnroll.status, 403);

    // 10. Views respect RLS (security_invoker = true) & SECURITY DEFINER functions set search_path
    const anonStats = await h.api('/rest/v1/hub_record_stats', { appCtx: anonNotesCtx });
    assert.equal(anonStats.status, 200);
    assert.equal(anonStats.data.length, 1);
    assert.equal(anonStats.data[0].visibility, 'public');

    const definerFuncs = await h.db.query(`
      SELECT n.nspname, p.proname, p.prosecdef, p.proconfig
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('hub_auth', 'hub_private', 'public')
        AND p.prosecdef = true
    `);
    assert.ok(definerFuncs.rows.length > 0);
    for (const fn of definerFuncs.rows) {
      assert.ok(
        Array.isArray(fn.proconfig) && fn.proconfig.some((c) => c.startsWith('search_path=')),
        `SECURITY DEFINER function ${fn.nspname}.${fn.proname} must fix search_path`
      );
    }

    // Verify all exposed public tables have RLS enabled + forced
    const rlsCheck = await h.db.query(`
      SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
    `);
    for (const tbl of rlsCheck.rows) {
      assert.equal(tbl.relrowsecurity, true, `${tbl.relname} must enable RLS`);
      assert.equal(tbl.relforcerowsecurity, true, `${tbl.relname} must force RLS`);
    }
    // 11. Viewer capability restriction & cross-app admin audit isolation
    const viewer = await h.createUser('viewer@example.com');
    await h.db.query(
      `INSERT INTO public.app_memberships (app_id, user_id, role, status, capabilities)
       VALUES ('notes-demo', $1, 'viewer', 'active', ARRAY['profile:read', 'records:read', 'storage:read']::text[])`,
      [viewer.user.id]
    );
    const viewerCtx = (await h.issueAppCtx('notes-demo', viewer.token)).data.appContextToken;
    const viewerWrite = await h.api('/rest/v1/app_records', {
      method: 'POST',
      token: viewer.token,
      appCtx: viewerCtx,
      body: { collection: 'notes', title: 'Viewer should fail' },
    });
    assert.equal(viewerWrite.status, 403, 'Viewer lacking records:write capability must be denied');

    const notesAdmin = await h.createUser('notes-admin@example.com');
    await h.addMembership('notes-demo', notesAdmin.user.id, 'admin');
    const notesAdminCtx = (await h.issueAppCtx('notes-demo', notesAdmin.token)).data.appContextToken;
    const crossAppAudit = await h.api('/rest/v1/audit_events', {
      token: notesAdmin.token,
      appCtx: notesAdminCtx,
    });
    assert.equal(crossAppAudit.status, 200);
    assert.ok(
      crossAppAudit.data.every((ev) => ev.app_id === 'notes-demo'),
      'Admin of notes-demo must only see audit events for notes-demo'
    );
  } finally {
    await h.cleanup();
  }
});
