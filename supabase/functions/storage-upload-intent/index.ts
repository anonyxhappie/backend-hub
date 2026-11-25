import { jsonResponse, errorResponse } from '../_shared/errors.ts';
import { buildCorsHeaders, extractBearer, requireEnv, signHmacJwt } from '../_shared/auth.ts';

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') {
    return errorResponse(405, 'METHOD_NOT_ALLOWED', 'POST required');
  }
  const supabaseUrl = requireEnv('SUPABASE_URL');
  const serviceRoleKey = requireEnv('SUPABASE_SERVICE_ROLE_KEY');
  const uploadSecret = requireEnv('HUB_UPLOAD_SECRET');
  const bearer = extractBearer(req);
  const appCtxToken = req.headers.get('x-app-context');
  if (!bearer || !appCtxToken) {
    return errorResponse(401, 'AUTH_REQUIRED', 'User Bearer token and X-App-Context are required');
  }

  // Verify user JWT via Supabase Auth API and call hub_private.reserve_storage_upload via PostgREST RPC
  const userRes = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: serviceRoleKey, Authorization: `Bearer ${bearer}` },
  });
  if (!userRes.ok) {
    return errorResponse(401, 'INVALID_TOKEN', 'Invalid user token');
  }
  const user = await userRes.json();

  const body = await req.json().catch(() => null);
  if (!body || !body.appId || !body.bucketId || !body.relativePath || !body.mimeType || !body.sizeBytes) {
    return errorResponse(400, 'VALIDATION_ERROR', 'Missing required upload intent fields');
  }

  const rpcRes = await fetch(`${supabaseUrl}/rest/v1/rpc/reserve_storage_upload`, {
    method: 'POST',
    headers: {
      apikey: serviceRoleKey,
      Authorization: `Bearer ${serviceRoleKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      p_app_id: body.appId,
      p_user_id: user.id,
      p_bucket_id: body.bucketId,
      p_relative_path: body.relativePath,
      p_mime_type: body.mimeType,
      p_size_bytes: body.sizeBytes,
      p_idempotency_key: req.headers.get('idempotency-key') || null,
      p_ttl_seconds: 300,
    }),
  });

  if (!rpcRes.ok) {
    const errText = await rpcRes.text();
    return errorResponse(400, 'RESERVATION_FAILED', errText);
  }

  const [reservation] = await rpcRes.json();
  const uploadToken = await signHmacJwt(
    {
      sub: user.id,
      app_id: body.appId,
      bucket_id: body.bucketId,
      object_id: reservation.object_id,
      object_path: reservation.object_path,
      reservation_id: reservation.reservation_id,
      max_bytes: body.sizeBytes,
      mime_type: body.mimeType,
    },
    uploadSecret,
    { ttlSeconds: 300, audience: 'backend-hub:storage-upload' }
  );

  return jsonResponse(200, { ...reservation, uploadToken }, buildCorsHeaders(req.headers.get('origin'), []));
});
