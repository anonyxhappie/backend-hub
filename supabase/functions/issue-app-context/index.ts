import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.1';
import { requireEnv, signHmacJwt } from '../_shared/auth.ts';
import { errorResponse, jsonResponse } from '../_shared/errors.ts';

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') {
    return errorResponse(405, 'METHOD_NOT_ALLOWED', 'Use POST');
  }

  const supabaseUrl = requireEnv('SUPABASE_URL');
  const anonKey = requireEnv('SUPABASE_ANON_KEY');
  const serviceRoleKey = requireEnv('SUPABASE_SERVICE_ROLE_KEY');
  const appCtxSecret = requireEnv('HUB_APP_CONTEXT_SECRET');

  const body = await req.json().catch(() => null);
  const appId = typeof body?.appId === 'string' ? body.appId.trim() : '';
  if (!appId) {
    return errorResponse(400, 'VALIDATION_ERROR', 'appId is required.');
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });
  const { data: appRow, error: appErr } = await admin
    .from('apps')
    .select('*')
    .eq('id', appId)
    .maybeSingle();

  if (appErr || !appRow || appRow.status !== 'active') {
    return errorResponse(403, 'FORBIDDEN', 'Application does not exist or is inactive.');
  }

  const origin = req.headers.get('origin');
  if (origin && !appRow.allowed_origins.includes(origin)) {
    return errorResponse(403, 'ORIGIN_NOT_ALLOWED', 'Origin is not registered for this app.');
  }

  const authHeader = req.headers.get('authorization');
  if (!authHeader) {
    if (!appRow.allow_public_read) {
      return errorResponse(401, 'AUTH_REQUIRED', 'Authentication required.');
    }
    const { token, exp } = await signHmacJwt(
      { sub: null, app_id: appId, app_role: 'anon', app_caps: ['records:read_public'], app_ctx_verified: 'true' },
      appCtxSecret,
      300,
      'backend-hub:app-context'
    );
    return jsonResponse(200, {
      appContextToken: token,
      appId,
      role: 'anon',
      capabilities: ['records:read_public'],
      expiresAt: exp,
    });
  }

  const userClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false },
  });
  const { data: userData, error: userErr } = await userClient.auth.getUser();
  if (userErr || !userData.user) {
    return errorResponse(401, 'AUTH_INVALID', 'Invalid user session.');
  }

  const { data: membership } = await admin
    .from('app_memberships')
    .select('*')
    .eq('app_id', appId)
    .eq('user_id', userData.user.id)
    .maybeSingle();

  if (!membership || membership.status !== 'active') {
    return errorResponse(403, 'FORBIDDEN', 'User is not an active member of this application.');
  }

  const { token, exp } = await signHmacJwt(
    {
      sub: userData.user.id,
      app_id: appId,
      app_role: membership.role,
      app_caps: membership.capabilities,
      app_ctx_verified: 'true',
    },
    appCtxSecret,
    300,
    'backend-hub:app-context'
  );

  return jsonResponse(200, {
    appContextToken: token,
    appId,
    role: membership.role,
    capabilities: membership.capabilities,
    expiresAt: exp,
  });
});
