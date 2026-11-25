import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { withDbContext as withRlsContext } from './db.js';
import {
  TOKEN_AUDIENCE,
  deriveSubkey,
  hashPassword,
  signJwt,
  verifyJwt,
  verifyPassword,
} from './crypto.js';
import { validateStorageObjectPath } from './storage-store.js';

const APP_ID_RE = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/;
const VALID_ENVS = new Set(['local', 'staging', 'production', 'test']);

export function validateServerConfig(rawConfig) {
  const env = rawConfig?.environment;
  if (!VALID_ENVS.has(env)) {
    throw new Error(`Invalid HUB_ENV "${env ?? ''}". Expected local, staging, production, or test.`);
  }
  const jwtSecret = rawConfig?.jwtSecret;
  if (typeof jwtSecret !== 'string' || jwtSecret.length < 24) {
    throw new Error('HUB_JWT_SECRET must be explicitly set and at least 24 characters.');
  }
  const serviceRoleKey = rawConfig?.serviceRoleKey;
  if (typeof serviceRoleKey !== 'string' || serviceRoleKey.length < 24) {
    throw new Error('HUB_SERVICE_ROLE_KEY must be explicitly set and at least 24 characters.');
  }
  return {
    environment: env,
    jwtSecret,
    serviceRoleKey,
    appCtxTtlSeconds: Number(rawConfig?.appCtxTtlSeconds ?? 300),
    userJwtTtlSeconds: Number(rawConfig?.userJwtTtlSeconds ?? 900),
    migrationsApplied: Number(rawConfig?.migrationsApplied ?? 0),
    dashboardOrigins: Array.isArray(rawConfig?.dashboardOrigins)
      ? rawConfig.dashboardOrigins
      : env === 'local'
        ? ['http://127.0.0.1:4102', 'http://localhost:4102']
        : [],
  };
}

function sendJson(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(payload);
}

function sendError(res, status, code, message, details = undefined, extraHeaders = {}) {
  sendJson(
    res,
    status,
    {
      error: {
        code,
        message,
        status,
        ...(details !== undefined ? { details } : {}),
      },
    },
    extraHeaders
  );
}

async function readBodyBuffer(req, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const err = new Error(`Payload exceeds maximum limit of ${maxBytes} bytes`);
      err.code = 'PAYLOAD_TOO_LARGE';
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJsonBody(req, maxBytes = 262144) {
  const buf = await readBodyBuffer(req, maxBytes);
  if (buf.length === 0) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    const err = new Error('Malformed JSON request body');
    err.code = 'VALIDATION_ERROR';
    err.status = 400;
    throw err;
  }
}

function mapDbError(err) {
  const msg = String(err?.message ?? 'Database error');
  if (msg.includes('QUOTA_EXCEEDED') || msg.includes('UPLOAD_TOO_LARGE')) {
    return { status: 429, code: 'QUOTA_EXCEEDED', message: msg };
  }
  if (msg.includes('INVALID_COLLECTION') || msg.includes('INVALID_PATH') || err?.code === '22023' || err?.code === '23514') {
    return { status: 400, code: 'VALIDATION_ERROR', message: msg };
  }
  if (err?.code === '23505') {
    return { status: 409, code: 'CONFLICT', message: msg };
  }
  if (
    err?.code === '42501' ||
    msg.includes('IMMUTABLE_') ||
    msg.includes('permission denied') ||
    msg.includes('row-level security') ||
    msg.includes('FORBIDDEN')
  ) {
    return { status: 403, code: 'FORBIDDEN', message: msg };
  }
  if (err?.code === '23503') {
    return { status: 400, code: 'CONSTRAINT_ERROR', message: msg };
  }
  return { status: 500, code: 'INTERNAL_ERROR', message: 'Internal database error' };
}

function verifyMagicBytes(mimeType, buf) {
  if (mimeType === 'image/png') {
    return buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
  }
  if (mimeType === 'image/jpeg') {
    return buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  }
  if (mimeType === 'application/pdf') {
    return buf.length >= 5 && buf.subarray(0, 5).toString('ascii') === '%PDF-';
  }
  if (mimeType === 'application/json') {
    try {
      JSON.parse(buf.toString('utf8'));
      return true;
    } catch {
      return false;
    }
  }
  return true;
}

function parseEqFilter(rawVal) {
  if (!rawVal) return null;
  return rawVal.startsWith('eq.') ? rawVal.slice(3) : rawVal;
}

export function createHubApp({ db, storageStore, config }) {
  const cfg = validateServerConfig(config);
  const keys = {
    user: deriveSubkey(cfg.jwtSecret, 'user-session'),
    appCtx: deriveSubkey(cfg.jwtSecret, 'app-context'),
    upload: deriveSubkey(cfg.jwtSecret, 'storage-upload'),
    download: deriveSubkey(cfg.jwtSecret, 'storage-download'),
  };

  // Per-app sliding-window rate limiter (in-memory per process)
  const rateWindows = new Map();

  function checkRateLimit(appId, limitRpm) {
    const now = Date.now();
    const cutoff = now - 60_000;
    const list = (rateWindows.get(appId) ?? []).filter((ts) => ts > cutoff);
    if (list.length >= limitRpm) {
      rateWindows.set(appId, list);
      return false;
    }
    list.push(now);
    rateWindows.set(appId, list);
    return true;
  }

  async function logAudit(appId, actorUserId, eventType, outcome, detail = {}) {
    try {
      await db.query(
        `INSERT INTO public.audit_events (app_id, actor_user_id, event_type, outcome, detail)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [appId || null, actorUserId || null, eventType, outcome, JSON.stringify(detail)]
      );
    } catch {
      // Never crash request handling if audit target app_id doesn't exist in FK
      await db.query(
        `INSERT INTO public.audit_events (app_id, actor_user_id, event_type, outcome, detail)
         VALUES (NULL, $1, $2, $3, $4::jsonb)`,
        [actorUserId || null, eventType, outcome, JSON.stringify({ requestedAppId: appId, ...detail })]
      ).catch(() => {});
    }
  }

  async function resolveCorsHeaders(origin) {
    if (!origin) return {};
    let allowed = cfg.dashboardOrigins.includes(origin);
    if (!allowed) {
      const res = await db.query(
        `SELECT 1 FROM public.apps WHERE status = 'active' AND $1 = ANY(allowed_origins) LIMIT 1`,
        [origin]
      );
      allowed = res.rows.length > 0;
    }
    if (!allowed) return {};
    return {
      'Access-Control-Allow-Origin': origin,
      'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-App-Context, Idempotency-Key',
    };
  }

  function extractBearer(req) {
    const auth = req.headers.authorization;
    if (!auth) return null;
    const match = String(auth).match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
  }

  function authenticateUser(req) {
    const token = extractBearer(req);
    if (!token) return null;
    const res = verifyJwt(token, keys.user, { audience: TOKEN_AUDIENCE.USER });
    if (!res.ok) {
      const err = new Error(res.error || 'Invalid user token');
      err.code = 'AUTH_INVALID';
      err.status = 401;
      throw err;
    }
    return res.payload;
  }

  function verifyAppContextHeader(req, userClaims) {
    const raw = req.headers['x-app-context'];
    if (!raw) return null;
    const res = verifyJwt(String(raw), keys.appCtx, { audience: TOKEN_AUDIENCE.APP_CONTEXT });
    if (!res.ok) {
      const err = new Error(res.error || 'Invalid app context token');
      err.code = 'INVALID_APP_CONTEXT';
      err.status = 401;
      throw err;
    }
    const ctx = res.payload;
    if (userClaims && ctx.sub !== userClaims.sub) {
      const err = new Error('App context token subject does not match authenticated user');
      err.code = 'FORBIDDEN';
      err.status = 403;
      throw err;
    }
    if (!userClaims && ctx.sub !== null) {
      const err = new Error('Authenticated app context token requires matching user session');
      err.code = 'AUTH_REQUIRED';
      err.status = 401;
      throw err;
    }
    return ctx;
  }

  function buildDbContext(userClaims, appCtxClaims) {
    const role = userClaims ? 'authenticated' : 'anon';
    if (!appCtxClaims) {
      return {
        role,
        claims: {
          sub: userClaims ? userClaims.sub : null,
          role,
        },
      };
    }
    return {
      role,
      claims: {
        sub: userClaims ? userClaims.sub : null,
        role,
        app_id: appCtxClaims.app_id,
        app_role: appCtxClaims.app_role,
        app_caps: appCtxClaims.app_caps ?? [],
        app_ctx_verified: 'true',
        app_ctx_exp: String(appCtxClaims.exp),
        app_ctx_jti: appCtxClaims.jti,
      },
    };
  }

  async function handleRequest(req, res) {
    const url = new URL(req.url || '/', 'http://localhost');
    const pathname = url.pathname;
    const method = req.method || 'GET';
    const origin = req.headers.origin ? String(req.headers.origin) : null;
    const cors = await resolveCorsHeaders(origin);

    if (method === 'OPTIONS') {
      res.writeHead(204, cors);
      res.end();
      return;
    }

    try {
      // Friendly API root & browser favicon
      if (method === 'GET' && pathname === '/') {
        return sendJson(
          res,
          200,
          {
            service: 'backend-hub',
            environment: cfg.environment,
            health: '/health',
            message: 'Backend Hub API server. Open the example static UI at its own origin (e.g. http://127.0.0.1:4100).',
          },
          cors
        );
      }
      if (method === 'GET' && pathname === '/favicon.ico') {
        res.writeHead(204, cors);
        res.end();
        return;
      }

      // Health checks (overall Hub or per-app via ?appId=<slug>)
      if (method === 'GET' && (pathname === '/health' || pathname === '/functions/v1/health')) {
        await db.query('SELECT 1');
        const requestedAppId = url.searchParams.get('appId');
        if (requestedAppId !== null) {
          const appId = requestedAppId.trim();
          if (!APP_ID_RE.test(appId)) {
            return sendError(res, 400, 'VALIDATION_ERROR', 'Invalid appId query parameter', undefined, cors);
          }
          const appRes = await db.query('SELECT id, name, status FROM public.apps WHERE id = $1', [appId]);
          const appRow = appRes.rows[0];
          if (!appRow) {
            return sendError(res, 404, 'APP_NOT_FOUND', `App "${appId}" is not registered`, undefined, cors);
          }
          return sendJson(
            res,
            200,
            {
              ok: appRow.status === 'active',
              environment: cfg.environment,
              db: 'ok',
              app: { id: appRow.id, name: appRow.name, status: appRow.status },
              migrationsApplied: cfg.migrationsApplied,
              timestamp: new Date().toISOString(),
            },
            cors
          );
        }
        return sendJson(
          res,
          200,
          {
            ok: true,
            environment: cfg.environment,
            db: 'ok',
            migrationsApplied: cfg.migrationsApplied,
            timestamp: new Date().toISOString(),
          },
          cors
        );
      }

      // Portfolio health & usage summary scoped strictly to the signed-in user's active memberships
      if (method === 'GET' && pathname === '/functions/v1/portfolio-health') {
        let userClaims;
        try {
          userClaims = authenticateUser(req);
        } catch (err) {
          return sendError(res, 401, 'AUTH_INVALID', err.message, undefined, cors);
        }
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required to inspect portfolio apps', undefined, cors);
        }

        const rowsRes = await db.query(
          `SELECT
             a.id, a.name, a.status, a.allowed_origins, a.allowed_collections,
             a.allow_self_enroll, a.allow_public_read,
             a.max_records_per_app, a.max_records_per_user,
             a.max_storage_bytes, a.max_user_storage_bytes, a.max_upload_bytes, a.rate_limit_rpm,
             m.role, m.capabilities,
             COALESCE(u.active_storage_bytes, 0) AS active_storage_bytes,
             COALESCE(u.reserved_storage_bytes, 0) AS reserved_storage_bytes,
             COALESCE(u.active_object_count, 0) AS active_object_count,
             COALESCE(u.record_count, 0) AS record_count,
             u.last_reconciled_at
           FROM public.app_memberships m
           JOIN public.apps a ON a.id = m.app_id
           LEFT JOIN public.app_usage u ON u.app_id = a.id
           WHERE m.user_id = $1 AND m.status = 'active'
           ORDER BY a.id ASC`,
          [userClaims.sub]
        );

        const apps = [];
        for (const r of rowsRes.rows) {
          let recentDenied24h = null;
          if (r.role === 'admin' || r.role === 'owner') {
            const auditRes = await db.query(
              `SELECT count(*)::integer AS cnt
               FROM public.audit_events
               WHERE app_id = $1 AND outcome = 'denied' AND created_at > pg_catalog.now() - interval '24 hours'`,
              [r.id]
            );
            recentDenied24h = auditRes.rows[0]?.cnt ?? 0;
          }
          apps.push({
            id: r.id,
            name: r.name,
            status: r.status,
            health: r.status === 'active' ? 'healthy' : r.status,
            role: r.role,
            capabilities: r.capabilities,
            allowedOrigins: r.allowed_origins,
            allowedCollections: r.allowed_collections,
            allowSelfEnroll: r.allow_self_enroll,
            allowPublicRead: r.allow_public_read,
            limits: {
              maxRecordsPerApp: r.max_records_per_app,
              maxRecordsPerUser: r.max_records_per_user,
              maxStorageBytes: Number(r.max_storage_bytes),
              maxUserStorageBytes: Number(r.max_user_storage_bytes),
              maxUploadBytes: Number(r.max_upload_bytes),
              rateLimitRpm: r.rate_limit_rpm,
            },
            usage: {
              recordCount: Number(r.record_count),
              activeObjectCount: Number(r.active_object_count),
              activeStorageBytes: Number(r.active_storage_bytes),
              reservedStorageBytes: Number(r.reserved_storage_bytes),
              lastReconciledAt: r.last_reconciled_at,
            },
            recentDenied24h,
          });
        }

        return sendJson(
          res,
          200,
          {
            environment: cfg.environment,
            db: 'ok',
            user: { id: userClaims.sub, email: userClaims.email },
            apps,
            timestamp: new Date().toISOString(),
          },
          cors
        );
      }

      // Auth: Signup
      if (method === 'POST' && pathname === '/auth/v1/signup') {
        const body = await readJsonBody(req);
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        if (!email || !email.includes('@') || password.length < 8) {
          return sendError(res, 400, 'VALIDATION_ERROR', 'Valid email and password (min 8 chars) required', undefined, cors);
        }
        const passwordHash = await hashPassword(password);
        const userId = randomUUID();
        try {
          const inserted = await db.query(
            `INSERT INTO auth.users (id, email, password_hash) VALUES ($1, $2, $3) RETURNING id, email, created_at`,
            [userId, email, passwordHash]
          );
          const user = inserted.rows[0];
          const expiresAt = Math.floor(Date.now() / 1000) + cfg.userJwtTtlSeconds;
          const token = signJwt(
            { sub: user.id, email: user.email, role: 'authenticated' },
            keys.user,
            { audience: TOKEN_AUDIENCE.USER, ttlSeconds: cfg.userJwtTtlSeconds }
          );
          await logAudit(null, user.id, 'auth.signup', 'allowed', {});
          return sendJson(res, 201, { accessToken: token, expiresAt, user }, cors);
        } catch (err) {
          if (err?.code === '23505') {
            return sendError(res, 409, 'EMAIL_EXISTS', 'Account already exists', undefined, cors);
          }
          throw err;
        }
      }

      // Auth: Login
      if (method === 'POST' && pathname === '/auth/v1/login') {
        const body = await readJsonBody(req);
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        const found = await db.query('SELECT id, email, password_hash FROM auth.users WHERE email = $1', [email]);
        const row = found.rows[0];
        if (!row || !(await verifyPassword(password, row.password_hash))) {
          await logAudit(null, row?.id ?? null, 'auth.login', 'denied', { email });
          return sendError(res, 401, 'AUTH_INVALID', 'Invalid email or password', undefined, cors);
        }
        const expiresAt = Math.floor(Date.now() / 1000) + cfg.userJwtTtlSeconds;
        const token = signJwt(
          { sub: row.id, email: row.email, role: 'authenticated' },
          keys.user,
          { audience: TOKEN_AUDIENCE.USER, ttlSeconds: cfg.userJwtTtlSeconds }
        );
        await logAudit(null, row.id, 'auth.login', 'allowed', {});
        return sendJson(
          res,
          200,
          { accessToken: token, expiresAt, user: { id: row.id, email: row.email } },
          cors
        );
      }

      // Auth: Get current user
      if (method === 'GET' && pathname === '/auth/v1/user') {
        let userClaims;
        try {
          userClaims = authenticateUser(req);
        } catch (err) {
          return sendError(res, 401, 'AUTH_INVALID', err.message, undefined, cors);
        }
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Bearer token required', undefined, cors);
        }
        return sendJson(res, 200, { user: { id: userClaims.sub, email: userClaims.email } }, cors);
      }

      // Trusted Function: issue-app-context
      if (method === 'POST' && pathname === '/functions/v1/issue-app-context') {
        let userClaims = null;
        try {
          userClaims = authenticateUser(req);
        } catch (err) {
          return sendError(res, 401, 'AUTH_INVALID', err.message, undefined, cors);
        }

        const body = await readJsonBody(req);
        const appId = typeof body.appId === 'string' ? body.appId.trim() : '';
        if (!APP_ID_RE.test(appId)) {
          return sendError(res, 400, 'VALIDATION_ERROR', 'Valid appId is required', undefined, cors);
        }

        const appRes = await db.query('SELECT * FROM public.apps WHERE id = $1', [appId]);
        const appRow = appRes.rows[0];
        if (!appRow || appRow.status !== 'active') {
          await logAudit(appId, userClaims?.sub ?? null, 'app_context.issue', 'denied', { reason: 'app_unavailable' });
          return sendError(res, 403, 'APP_UNAVAILABLE', 'App is missing or inactive', undefined, cors);
        }

        if (!checkRateLimit(appId, appRow.rate_limit_rpm)) {
          return sendError(res, 429, 'RATE_LIMITED', 'App rate limit exceeded', undefined, {
            ...cors,
            'Retry-After': '60',
          });
        }

        if (origin && appRow.allowed_origins.length > 0 && !appRow.allowed_origins.includes(origin)) {
          await logAudit(appId, userClaims?.sub ?? null, 'app_context.issue', 'denied', {
            reason: 'origin_not_allowed',
            origin,
          });
          return sendError(res, 403, 'ORIGIN_NOT_ALLOWED', 'Browser Origin is not allowed for this app', undefined, cors);
        }

        let appRole = 'anon';
        let appCaps = ['records:read_public'];
        let membership = null;

        if (userClaims) {
          const memRes = await db.query(
            'SELECT app_id, user_id, role, status, capabilities FROM public.app_memberships WHERE app_id = $1 AND user_id = $2',
            [appId, userClaims.sub]
          );
          const m = memRes.rows[0];
          if (!m || m.status !== 'active') {
            await logAudit(appId, userClaims.sub, 'app_context.issue', 'denied', { reason: 'no_active_membership' });
            return sendError(res, 403, 'MEMBERSHIP_REQUIRED', 'User has no active membership for this app', undefined, cors);
          }
          appRole = m.role;
          appCaps = m.capabilities;
          membership = m;
        } else if (!appRow.allow_public_read) {
          await logAudit(appId, null, 'app_context.issue', 'denied', { reason: 'auth_required' });
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication is required for this app', undefined, cors);
        }

        const expiresAt = Math.floor(Date.now() / 1000) + cfg.appCtxTtlSeconds;
        const token = signJwt(
          {
            sub: userClaims ? userClaims.sub : null,
            app_id: appId,
            app_role: appRole,
            app_caps: appCaps,
            app_ctx_verified: 'true',
            origin_at_issue: origin,
          },
          keys.appCtx,
          { audience: TOKEN_AUDIENCE.APP_CONTEXT, ttlSeconds: cfg.appCtxTtlSeconds }
        );

        await logAudit(appId, userClaims?.sub ?? null, 'app_context.issue', 'allowed', { appRole });
        return sendJson(
          res,
          200,
          {
            appContextToken: token,
            expiresAt,
            app: {
              id: appRow.id,
              name: appRow.name,
              allowedCollections: appRow.allowed_collections,
              allowPublicRead: appRow.allow_public_read,
              allowSelfEnroll: appRow.allow_self_enroll,
            },
            membership,
          },
          cors
        );
      }

      // Trusted Function: enroll (self-enroll as member ONLY if allow_self_enroll = true)
      if (method === 'POST' && pathname === '/functions/v1/enroll') {
        let userClaims;
        try {
          userClaims = authenticateUser(req);
        } catch (err) {
          return sendError(res, 401, 'AUTH_INVALID', err.message, undefined, cors);
        }
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }

        const body = await readJsonBody(req);
        const appId = typeof body.appId === 'string' ? body.appId.trim() : '';
        if (!APP_ID_RE.test(appId)) {
          return sendError(res, 400, 'VALIDATION_ERROR', 'Valid appId is required', undefined, cors);
        }

        const result = await withRlsContext(
          db,
          { role: 'authenticated', claims: { sub: userClaims.sub, role: 'authenticated' } },
          (tx) => tx.query('SELECT * FROM public.hub_self_enroll($1)', [appId])
        );
        await logAudit(appId, userClaims.sub, 'app.enroll', 'allowed', { role: 'member' });
        return sendJson(res, 200, { membership: result.rows[0] }, cors);
      }

      // Trusted Function: quota-reconcile (service_role key OR scoped app admin/owner)
      if (method === 'POST' && pathname === '/functions/v1/quota-reconcile') {
        const body = await readJsonBody(req);
        const serviceKey = req.headers['x-service-role-key'];
        if (serviceKey && serviceKey === cfg.serviceRoleKey) {
          const targetApp = typeof body.appId === 'string' ? body.appId : null;
          const rows = await db.query('SELECT * FROM hub_private.reconcile_app_usage($1)', [targetApp]);
          return sendJson(res, 200, { reconciled: rows.rows }, cors);
        }

        let userClaims;
        let appCtx;
        try {
          userClaims = authenticateUser(req);
          if (!userClaims) return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
          appCtx = verifyAppContextHeader(req, userClaims);
        } catch (err) {
          return sendError(res, err.status || 401, err.code || 'AUTH_INVALID', err.message, undefined, cors);
        }

        const targetAppId = appCtx?.app_id || (typeof body.appId === 'string' ? body.appId.trim() : '');
        if (!targetAppId) {
          return sendError(res, 403, 'MISSING_APP_CONTEXT', 'x-app-context or appId required', undefined, cors);
        }

        const isAdmin = await db.query(
          `SELECT 1 FROM public.app_memberships WHERE app_id = $1 AND user_id = $2 AND status = 'active' AND role IN ('admin', 'owner')`,
          [targetAppId, userClaims.sub]
        );
        if (isAdmin.rows.length === 0) {
          return sendError(res, 403, 'FORBIDDEN', 'Admin/owner membership or service role required', undefined, cors);
        }
        const rows = await db.query('SELECT * FROM hub_private.reconcile_app_usage($1)', [targetAppId]);
        return sendJson(res, 200, { reconciled: rows.rows }, cors);
      }

      // Signed Storage Download (token-scoped bearer URL, private files)
      if (method === 'GET' && pathname === '/storage/v1/object/sign') {
        const rawToken = url.searchParams.get('token');
        const dlRes = verifyJwt(rawToken, keys.download, { audience: TOKEN_AUDIENCE.STORAGE_DOWNLOAD });
        if (!dlRes.ok) {
          return sendError(res, 403, 'INVALID_SIGNED_URL', dlRes.error, undefined, cors);
        }
        const claims = dlRes.payload;

        const objRes = await db.query(
          `SELECT o.*, a.status AS app_status
           FROM public.storage_objects o
           JOIN public.apps a ON a.id = o.app_id
           WHERE o.id = $1`,
          [claims.object_id]
        );
        const obj = objRes.rows[0];
        if (!obj || obj.status !== 'active' || obj.app_status !== 'active' || obj.object_path !== claims.object_path) {
          return sendError(res, 404, 'OBJECT_NOT_FOUND', 'Storage object is unavailable', undefined, cors);
        }

        const bytes = await storageStore.readObject(obj.bucket_id, obj.object_path);
        res.writeHead(200, {
          ...cors,
          'Content-Type': obj.mime_type,
          'Content-Length': String(bytes.byteLength),
          'Cache-Control': 'private, no-store',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'none'",
          'Content-Disposition': `attachment; filename="${obj.relative_path.split('/').pop()}"`,
        });
        res.end(bytes);
        return;
      }

      // Storage Binary Upload (requires server-minted uploadToken)
      if (method === 'PUT' && pathname === '/storage/v1/object/upload') {
        const rawToken = url.searchParams.get('token') || req.headers['x-upload-token'];
        const upRes = verifyJwt(String(rawToken || ''), keys.upload, {
          audience: TOKEN_AUDIENCE.STORAGE_UPLOAD,
        });
        if (!upRes.ok) {
          return sendError(res, 403, 'INVALID_UPLOAD_TOKEN', upRes.error, undefined, cors);
        }
        const uploadClaims = upRes.payload;

        const buf = await readBodyBuffer(req, Number(uploadClaims.max_bytes));
        if (buf.byteLength === 0) {
          return sendError(res, 400, 'VALIDATION_ERROR', 'Uploaded file cannot be empty', undefined, cors);
        }
        if (!verifyMagicBytes(uploadClaims.mime_type, buf)) {
          return sendError(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'File content does not match declared MIME type', undefined, cors);
        }

        validateStorageObjectPath(uploadClaims.object_path);
        const stored = await storageStore.putObject(uploadClaims.bucket_id, uploadClaims.object_path, buf);

        try {
          const committed = await db.query(
            'SELECT * FROM hub_private.commit_storage_upload($1, $2, $3)',
            [uploadClaims.object_id, stored.sizeBytes, stored.sha256]
          );
          return sendJson(res, 200, { object: committed.rows[0] }, cors);
        } catch (err) {
          await storageStore.deleteObject(uploadClaims.bucket_id, uploadClaims.object_path).catch(() => {});
          throw err;
        }
      }

      // Routes below require verified app context (and user session when authenticated)
      const isScopedRoute = pathname.startsWith('/rest/v1/') || pathname.startsWith('/functions/v1/');
      if (!isScopedRoute) {
        return sendError(res, 404, 'NOT_FOUND', `No route matches ${method} ${pathname}`, undefined, cors);
      }

      let userClaims = null;
      let appCtx = null;
      try {
        userClaims = authenticateUser(req);
        appCtx = verifyAppContextHeader(req, userClaims);
      } catch (err) {
        return sendError(res, err.status || 401, err.code || 'AUTH_INVALID', err.message, undefined, cors);
      }

      if (!appCtx) {
        return sendError(
          res,
          403,
          'MISSING_APP_CONTEXT',
          'Server-issued x-app-context token is required',
          undefined,
          cors
        );
      }

      const appMetaRes = await db.query('SELECT rate_limit_rpm FROM public.apps WHERE id = $1', [appCtx.app_id]);
      const limitRpm = appMetaRes.rows[0]?.rate_limit_rpm ?? 120;
      if (!checkRateLimit(appCtx.app_id, limitRpm)) {
        return sendError(res, 429, 'RATE_LIMITED', 'App rate limit exceeded', undefined, {
          ...cors,
          'Retry-After': '60',
        });
      }

      const dbCtx = buildDbContext(userClaims, appCtx);

      // Trusted Function: app-capabilities
      if (method === 'GET' && pathname === '/functions/v1/app-capabilities') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        const result = await withRlsContext(db, dbCtx, async (tx) => {
          const [appR, memR, usageR] = await Promise.all([
            tx.query(
              `SELECT id, name, allowed_collections, max_records_per_app, max_records_per_user,
                      max_storage_bytes, max_user_storage_bytes, max_upload_bytes, allowed_mime_types
               FROM public.apps WHERE id = hub_auth.current_app_id()`
            ),
            tx.query(
              `SELECT app_id, user_id, role, status, capabilities
               FROM public.app_memberships WHERE app_id = hub_auth.current_app_id() AND user_id = hub_auth.current_user_id()`
            ),
            tx.query(`SELECT * FROM public.app_usage WHERE app_id = hub_auth.current_app_id()`),
          ]);
          return {
            app: appR.rows[0] ?? null,
            membership: memR.rows[0] ?? null,
            usage: usageR.rows[0] ?? null,
          };
        });
        return sendJson(res, 200, result, cors);
      }

      // Trusted Function: trusted-note-summary (example trusted server operation)
      if (method === 'POST' && pathname === '/functions/v1/trusted-note-summary') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        const summary = await withRlsContext(db, dbCtx, async (tx) => {
          const stats = await tx.query('SELECT * FROM public.hub_record_stats');
          const files = await tx.query(
            'SELECT count(*)::integer AS file_count, COALESCE(SUM(size_bytes), 0)::bigint AS total_bytes FROM public.storage_objects'
          );
          return {
            appId: appCtx.app_id,
            userId: userClaims.sub,
            recordStats: stats.rows,
            storageStats: files.rows[0],
            generatedAt: new Date().toISOString(),
          };
        });
        return sendJson(res, 200, summary, cors);
      }

      // Trusted Function: storage-upload-intent
      if (method === 'POST' && pathname === '/functions/v1/storage-upload-intent') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        const body = await readJsonBody(req);
        const bucketId = typeof body.bucketId === 'string' ? body.bucketId.trim() : '';
        const relativePath = typeof body.relativePath === 'string' ? body.relativePath.trim() : '';
        const mimeType = typeof body.mimeType === 'string' ? body.mimeType.trim() : '';
        const sizeBytes = Number(body.sizeBytes);
        const idempotencyKey = req.headers['idempotency-key']
          ? String(req.headers['idempotency-key'])
          : typeof body.idempotencyKey === 'string'
            ? body.idempotencyKey
            : null;

        const reserved = await db.query(
          'SELECT * FROM hub_private.reserve_storage_upload($1, $2, $3, $4, $5, $6, $7, $8)',
          [appCtx.app_id, userClaims.sub, bucketId, relativePath, mimeType, sizeBytes, idempotencyKey, 300]
        );
        const row = reserved.rows[0];
        const uploadToken = signJwt(
          {
            sub: userClaims.sub,
            app_id: appCtx.app_id,
            bucket_id: bucketId,
            object_id: row.object_id,
            object_path: row.object_path,
            reservation_id: row.reservation_id,
            max_bytes: sizeBytes,
            mime_type: mimeType,
          },
          keys.upload,
          { audience: TOKEN_AUDIENCE.STORAGE_UPLOAD, ttlSeconds: 300 }
        );

        return sendJson(
          res,
          201,
          {
            reservationId: row.reservation_id,
            objectId: row.object_id,
            objectPath: row.object_path,
            expiresAt: row.expires_at,
            reused: row.reused,
            uploadToken,
          },
          cors
        );
      }

      // Trusted Function: storage-signed-url
      if (method === 'POST' && pathname === '/functions/v1/storage-signed-url') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        const body = await readJsonBody(req);
        const objectId = typeof body.objectId === 'string' ? body.objectId.trim() : '';
        const ttl = Math.max(10, Math.min(Number(body.expiresInSeconds ?? 60), 300));
        if (!objectId) {
          return sendError(res, 400, 'VALIDATION_ERROR', 'objectId is required', undefined, cors);
        }

        // Enforce PostgreSQL RLS on object lookup!
        const objRes = await withRlsContext(db, dbCtx, (tx) =>
          tx.query('SELECT id, bucket_id, app_id, owner_id, object_path FROM public.storage_objects WHERE id = $1', [
            objectId,
          ])
        );
        const obj = objRes.rows[0];
        if (!obj) {
          return sendError(res, 404, 'OBJECT_NOT_FOUND', 'Object not found or not accessible', undefined, cors);
        }

        const expiresAt = Math.floor(Date.now() / 1000) + ttl;
        const token = signJwt(
          {
            object_id: obj.id,
            bucket_id: obj.bucket_id,
            app_id: obj.app_id,
            owner_id: obj.owner_id,
            object_path: obj.object_path,
          },
          keys.download,
          { audience: TOKEN_AUDIENCE.STORAGE_DOWNLOAD, ttlSeconds: ttl }
        );

        return sendJson(
          res,
          200,
          {
            signedUrl: `/storage/v1/object/sign?token=${encodeURIComponent(token)}`,
            expiresAt,
          },
          cors
        );
      }

      // Trusted Function: delete storage object
      if (method === 'DELETE' && pathname === '/functions/v1/storage-object') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        const objectId = url.searchParams.get('objectId');
        if (!objectId) {
          return sendError(res, 400, 'VALIDATION_ERROR', 'objectId query param required', undefined, cors);
        }
        if (!appCtx.app_caps?.includes('storage:delete') && !appCtx.app_caps?.includes('*')) {
          return sendError(res, 403, 'FORBIDDEN', 'Missing storage:delete capability', undefined, cors);
        }

        const objRes = await withRlsContext(db, dbCtx, (tx) =>
          tx.query('SELECT id, bucket_id, app_id, owner_id, object_path FROM public.storage_objects WHERE id = $1', [
            objectId,
          ])
        );
        const obj = objRes.rows[0];
        if (!obj) {
          return sendError(res, 404, 'OBJECT_NOT_FOUND', 'Object not found or not accessible', undefined, cors);
        }

        await db.query(`UPDATE public.storage_objects SET status = 'deleted' WHERE id = $1`, [obj.id]);
        await storageStore.deleteObject(obj.bucket_id, obj.object_path);
        await db.query('SELECT * FROM hub_private.reconcile_app_usage($1)', [obj.app_id]);
        return sendJson(res, 200, { deleted: true, objectId: obj.id }, cors);
      }

      // REST / RLS endpoints
      if (pathname === '/rest/v1/app_profiles') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        if (method === 'GET') {
          const userIdFilter = parseEqFilter(url.searchParams.get('user_id'));
          const rows = await withRlsContext(db, dbCtx, (tx) => {
            if (userIdFilter) {
              return tx.query('SELECT * FROM public.app_profiles WHERE user_id = $1 LIMIT 50', [userIdFilter]);
            }
            return tx.query('SELECT * FROM public.app_profiles LIMIT 50');
          });
          return sendJson(res, 200, rows.rows, cors);
        }
        if (method === 'POST') {
          const body = await readJsonBody(req);
          const targetAppId = body.app_id ?? appCtx.app_id;
          const targetUserId = body.user_id ?? userClaims.sub;
          const inserted = await withRlsContext(db, dbCtx, (tx) =>
            tx.query(
              `INSERT INTO public.app_profiles (app_id, user_id, display_name, bio, avatar_path, metadata)
               VALUES ($1, $2, $3, $4, $5, $6::jsonb)
               RETURNING *`,
              [
                targetAppId,
                targetUserId,
                body.display_name,
                body.bio ?? '',
                body.avatar_path ?? null,
                JSON.stringify(body.metadata ?? {}),
              ]
            )
          );
          return sendJson(res, 201, inserted.rows[0], cors);
        }
        if (method === 'PATCH') {
          const body = await readJsonBody(req);
          const userIdFilter = parseEqFilter(url.searchParams.get('user_id')) ?? userClaims.sub;
          const allowedCols = ['display_name', 'bio', 'avatar_path', 'metadata', 'app_id', 'user_id'];
          const updates = [];
          const params = [];
          for (const col of allowedCols) {
            if (Object.hasOwn(body, col)) {
              params.push(col === 'metadata' ? JSON.stringify(body[col]) : body[col]);
              updates.push(`${col} = $${params.length}${col === 'metadata' ? '::jsonb' : ''}`);
            }
          }
          if (updates.length === 0) {
            return sendError(res, 400, 'VALIDATION_ERROR', 'No fields provided for update', undefined, cors);
          }
          params.push(userIdFilter);
          const updated = await withRlsContext(db, dbCtx, (tx) =>
            tx.query(
              `UPDATE public.app_profiles SET ${updates.join(', ')} WHERE user_id = $${params.length} RETURNING *`,
              params
            )
          );
          return sendJson(res, 200, updated.rows, cors);
        }
        if (method === 'DELETE') {
          const userIdFilter = parseEqFilter(url.searchParams.get('user_id')) ?? userClaims.sub;
          const deleted = await withRlsContext(db, dbCtx, (tx) =>
            tx.query('DELETE FROM public.app_profiles WHERE user_id = $1 RETURNING *', [userIdFilter])
          );
          return sendJson(res, 200, deleted.rows, cors);
        }
      }

      if (pathname === '/rest/v1/app_records') {
        if (method === 'GET') {
          const conds = [];
          const params = [];
          for (const key of ['id', 'app_id', 'owner_id', 'collection', 'visibility']) {
            const v = parseEqFilter(url.searchParams.get(key));
            if (v) {
              params.push(v);
              conds.push(`${key} = $${params.length}`);
            }
          }
          const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit') ?? 50), 200));
          params.push(limit);
          const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
          const rows = await withRlsContext(db, dbCtx, (tx) =>
            tx.query(
              `SELECT * FROM public.app_records ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
              params
            )
          );
          return sendJson(res, 200, rows.rows, cors);
        }

        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }

        if (method === 'POST') {
          const body = await readJsonBody(req);
          const targetAppId = body.app_id ?? appCtx.app_id;
          const targetOwnerId = body.owner_id ?? userClaims.sub;
          const inserted = await withRlsContext(db, dbCtx, (tx) =>
            tx.query(
              `INSERT INTO public.app_records (app_id, owner_id, collection, visibility, title, payload)
               VALUES ($1, $2, $3, $4, $5, $6::jsonb)
               RETURNING *`,
              [
                targetAppId,
                targetOwnerId,
                body.collection,
                body.visibility ?? 'private',
                body.title,
                JSON.stringify(body.payload ?? {}),
              ]
            )
          );
          return sendJson(res, 201, inserted.rows[0], cors);
        }

        if (method === 'PATCH') {
          const body = await readJsonBody(req);
          const idFilter = parseEqFilter(url.searchParams.get('id'));
          if (!idFilter) {
            return sendError(res, 400, 'VALIDATION_ERROR', 'id filter is required for PATCH', undefined, cors);
          }
          const patchCols = ['collection', 'visibility', 'title', 'payload', 'app_id', 'owner_id'];
          const sets = [];
          const params = [];
          for (const col of patchCols) {
            if (Object.hasOwn(body, col)) {
              params.push(col === 'payload' ? JSON.stringify(body[col]) : body[col]);
              sets.push(`${col} = $${params.length}${col === 'payload' ? '::jsonb' : ''}`);
            }
          }
          if (sets.length === 0) {
            return sendError(res, 400, 'VALIDATION_ERROR', 'No fields provided for update', undefined, cors);
          }
          params.push(idFilter);
          const updated = await withRlsContext(db, dbCtx, (tx) =>
            tx.query(
              `UPDATE public.app_records SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING *`,
              params
            )
          );
          if (updated.rows.length === 0) {
            return sendError(res, 404, 'NOT_FOUND', 'Record not found or access denied', undefined, cors);
          }
          return sendJson(res, 200, updated.rows, cors);
        }

        if (method === 'DELETE') {
          const idFilter = parseEqFilter(url.searchParams.get('id'));
          if (!idFilter) {
            return sendError(res, 400, 'VALIDATION_ERROR', 'id filter is required for DELETE', undefined, cors);
          }
          const deleted = await withRlsContext(db, dbCtx, (tx) =>
            tx.query('DELETE FROM public.app_records WHERE id = $1 RETURNING *', [idFilter])
          );
          if (deleted.rows.length === 0) {
            return sendError(res, 404, 'NOT_FOUND', 'Record not found or access denied', undefined, cors);
          }
          return sendJson(res, 200, deleted.rows, cors);
        }
      }

      if (pathname === '/rest/v1/app_memberships') {
        if (!userClaims) {
          return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        }
        if (method === 'GET') {
          const rows = await withRlsContext(db, dbCtx, (tx) => tx.query('SELECT * FROM public.app_memberships'));
          return sendJson(res, 200, rows.rows, cors);
        }
        if (method === 'POST') {
          const body = await readJsonBody(req);
          const inserted = await withRlsContext(db, dbCtx, (tx) =>
            tx.query(
              'INSERT INTO public.app_memberships (app_id, user_id, role, status) VALUES ($1, $2, $3, $4) RETURNING *',
              [body.app_id ?? appCtx.app_id, body.user_id ?? userClaims.sub, body.role ?? 'owner', body.status ?? 'active']
            )
          );
          return sendJson(res, 201, inserted.rows[0], cors);
        }
        if (method === 'PATCH') {
          const body = await readJsonBody(req);
          const updated = await withRlsContext(db, dbCtx, (tx) =>
            tx.query('UPDATE public.app_memberships SET role = $1 WHERE user_id = $2 RETURNING *', [
              body.role,
              userClaims.sub,
            ])
          );
          return sendJson(res, 200, updated.rows, cors);
        }
      }

      if (method === 'GET' && pathname === '/rest/v1/storage_objects') {
        if (!userClaims) return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        const rows = await withRlsContext(db, dbCtx, (tx) =>
          tx.query('SELECT * FROM public.storage_objects ORDER BY created_at DESC LIMIT 100')
        );
        return sendJson(res, 200, rows.rows, cors);
      }

      if (method === 'GET' && pathname === '/rest/v1/app_usage') {
        if (!userClaims) return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        const rows = await withRlsContext(db, dbCtx, (tx) => tx.query('SELECT * FROM public.app_usage'));
        return sendJson(res, 200, rows.rows, cors);
      }

      if (method === 'GET' && pathname === '/rest/v1/audit_events') {
        if (!userClaims) return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        const rows = await withRlsContext(db, dbCtx, (tx) =>
          tx.query('SELECT * FROM public.audit_events ORDER BY id DESC LIMIT 100')
        );
        return sendJson(res, 200, rows.rows, cors);
      }

      if (method === 'GET' && pathname === '/rest/v1/app_member_summary') {
        if (!userClaims) return sendError(res, 401, 'AUTH_REQUIRED', 'Authentication required', undefined, cors);
        const rows = await withRlsContext(db, dbCtx, (tx) => tx.query('SELECT * FROM public.app_member_summary'));
        return sendJson(res, 200, rows.rows, cors);
      }

      if (method === 'GET' && pathname === '/rest/v1/hub_record_stats') {
        const rows = await withRlsContext(db, dbCtx, (tx) => tx.query('SELECT * FROM public.hub_record_stats'));
        return sendJson(res, 200, rows.rows, cors);
      }

      return sendError(res, 404, 'NOT_FOUND', `No route matches ${method} ${pathname}`, undefined, cors);
    } catch (err) {
      if (err?.status && err?.code) {
        return sendError(res, err.status, err.code, err.message, undefined, cors);
      }
      const mapped = mapDbError(err);
      return sendError(res, mapped.status, mapped.code, mapped.message, undefined, cors);
    }
  }

  return {
    handleRequest,
    createServer() {
      return http.createServer((req, res) => {
        handleRequest(req, res).catch((err) => {
          sendError(res, 500, 'INTERNAL_ERROR', err?.message || 'Unhandled server error');
        });
      });
    },
  };
}

export async function startHubServer({ db, storage, config, port = 0, host = '127.0.0.1' }) {
  const app = createHubApp({ db, storageStore: storage, config });
  const server = app.createServer();
  await new Promise((resolve) => server.listen(port, host, resolve));
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  return {
    url: `http://${host}:${actualPort}`,
    port: actualPort,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(resolve);
      }),
  };
}
