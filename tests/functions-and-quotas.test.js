import test from 'node:test';
import assert from 'node:assert/strict';
import { createTestHarness } from './helpers/harness.js';

test('trusted functions: origin validation, suspended app denial, record quotas, rate limits, and audit access', async () => {
  const h = await createTestHarness();
  try {
    const member = await h.createUser('member@example.com');
    const admin = await h.createUser('admin@example.com');
    await h.addMembership('notes-demo', member.user.id, 'member');
    await h.addMembership('notes-demo', admin.user.id, 'admin');

    // 1. Disallowed Origin rejected on issue-app-context and logged to audit_events
    const badOrigin = await h.issueAppCtx('notes-demo', member.token, 'https://evil-phish.example');
    assert.equal(badOrigin.status, 403);
    assert.equal(badOrigin.data.error.code, 'ORIGIN_NOT_ALLOWED');

    // Allowed Origin succeeds
    const goodOrigin = await h.issueAppCtx('notes-demo', member.token, 'http://127.0.0.1:4100');
    assert.equal(goodOrigin.status, 200);
    const memberCtx = goodOrigin.data.appContextToken;
    const adminCtx = (await h.issueAppCtx('notes-demo', admin.token, 'http://127.0.0.1:4100')).data.appContextToken;

    // 2. Audit events visible ONLY to admin/owner, not regular members
    const memberAudit = await h.api('/rest/v1/audit_events', { token: member.token, appCtx: memberCtx });
    assert.equal(memberAudit.status, 200);
    assert.deepEqual(memberAudit.data, []);

    const adminAudit = await h.api('/rest/v1/audit_events', { token: admin.token, appCtx: adminCtx });
    assert.equal(adminAudit.status, 200);
    assert.ok(adminAudit.data.some((e) => e.outcome === 'denied' && e.detail?.reason === 'origin_not_allowed'));

    // 3. Per-user record quota enforced atomically in PostgreSQL
    await h.db.query(`UPDATE public.apps SET max_records_per_user = 2 WHERE id = 'notes-demo'`);
    for (const i of [1, 2]) {
      const r = await h.api('/rest/v1/app_records', {
        method: 'POST',
        token: member.token,
        appCtx: memberCtx,
        body: { collection: 'notes', title: `Note ${i}` },
      });
      assert.equal(r.status, 201);
    }
    const overQuota = await h.api('/rest/v1/app_records', {
      method: 'POST',
      token: member.token,
      appCtx: memberCtx,
      body: { collection: 'notes', title: 'Note 3 over quota' },
    });
    assert.equal(overQuota.status, 429);
    assert.equal(overQuota.data.error.code, 'QUOTA_EXCEEDED');

    // 4. Disallowed collection rejected
    const badCollection = await h.api('/rest/v1/app_records', {
      method: 'POST',
      token: admin.token,
      appCtx: adminCtx,
      body: { collection: 'secrets', title: 'Wrong collection' },
    });
    assert.equal(badCollection.status, 400);

    // 5. Suspended app blocks both new app-context issuance and existing app-context queries via RLS!
    await h.db.query(`UPDATE public.apps SET status = 'suspended' WHERE id = 'notes-demo'`);
    const suspendedCtxAttempt = await h.issueAppCtx('notes-demo', member.token);
    assert.equal(suspendedCtxAttempt.status, 403);

    const existingTokenQuery = await h.api('/rest/v1/app_records', { token: member.token, appCtx: memberCtx });
    assert.equal(existingTokenQuery.status, 200);
    assert.deepEqual(existingTokenQuery.data, []);

    // Reactivate app and verify per-app rate limiting
    await h.db.query(`UPDATE public.apps SET status = 'active', rate_limit_rpm = 3 WHERE id = 'notes-demo'`);
    const rlStatuses = [];
    for (let i = 0; i < 5; i++) {
      const r = await h.api('/functions/v1/app-capabilities', { token: member.token, appCtx: memberCtx });
      rlStatuses.push(r.status);
    }
    assert.ok(rlStatuses.includes(429), 'Exceeding rate_limit_rpm must trigger 429 RATE_LIMITED');

    // Root returns API info and unknown non-scoped paths return 404 rather than 403 MISSING_APP_CONTEXT
    const rootRes = await h.api('/');
    assert.equal(rootRes.status, 200);
    assert.equal(rootRes.data.service, 'backend-hub');

    const unknownRes = await h.api('/unknown-path');
    assert.equal(unknownRes.status, 404);

    // Per-app health check & portfolio-health endpoint
    const appHealthOk = await h.api('/functions/v1/health?appId=notes-demo');
    assert.equal(appHealthOk.status, 200);
    assert.equal(appHealthOk.data.ok, true);
    assert.equal(appHealthOk.data.app.id, 'notes-demo');

    const appHealthMissing = await h.api('/functions/v1/health?appId=nonexistent-app');
    assert.equal(appHealthMissing.status, 404);

    const anonPortfolio = await h.api('/functions/v1/portfolio-health');
    assert.equal(anonPortfolio.status, 401);

    const memberPortfolio = await h.api('/functions/v1/portfolio-health', { token: member.token });
    assert.equal(memberPortfolio.status, 200);
    assert.deepEqual(
      memberPortfolio.data.apps.map((a) => a.id),
      ['notes-demo']
    );
    assert.equal(memberPortfolio.data.apps[0].recentDenied24h, null, 'Regular member must not see admin audit counts');

    const adminPortfolio = await h.api('/functions/v1/portfolio-health', { token: admin.token });
    assert.equal(adminPortfolio.status, 200);
    assert.equal(typeof adminPortfolio.data.apps[0].recentDenied24h, 'number');

    const adminDashReconcile = await h.api('/functions/v1/quota-reconcile', {
      method: 'POST',
      token: admin.token,
      body: { appId: 'notes-demo' },
    });
    assert.equal(adminDashReconcile.status, 200);
  } finally {
    await h.cleanup();
  }
});
