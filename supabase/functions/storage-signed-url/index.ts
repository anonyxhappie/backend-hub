import { jsonResponse, errorResponse } from '../_shared/errors.ts';
import { extractBearer, requireEnv } from '../_shared/auth.ts';

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') {
    return errorResponse(405, 'METHOD_NOT_ALLOWED', 'POST required');
  }
  const supabaseUrl = requireEnv('SUPABASE_URL');
  const serviceRoleKey = requireEnv('SUPABASE_SERVICE_ROLE_KEY');
  const bearer = extractBearer(req);
  if (!bearer) {
    return errorResponse(401, 'AUTH_REQUIRED', 'User Bearer token is required');
  }

  const body = await req.json().catch(() => null);
  if (!body || !body.objectId) {
    return errorResponse(400, 'VALIDATION_ERROR', 'objectId is required');
  }

  const ttl = Math.max(10, Math.min(Number(body.expiresInSeconds || 60), 300));
  const userRes = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: serviceRoleKey, Authorization: `Bearer ${bearer}` },
  });
  if (!userRes.ok) {
    return errorResponse(401, 'INVALID_TOKEN', 'Invalid user token');
  }
  const user = await userRes.json();

  const objRes = await fetch(
    `${supabaseUrl}/rest/v1/storage_objects?id=eq.${encodeURIComponent(body.objectId)}&status=eq.active&select=*`,
    { headers: { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}` } }
  );
  const rows = await objRes.json();
  const obj = Array.isArray(rows) ? rows[0] : null;
  if (!obj || obj.owner_id !== user.id) {
    return errorResponse(404, 'NOT_FOUND', 'Object not found or access denied');
  }

  const signRes = await fetch(
    `${supabaseUrl}/storage/v1/object/sign/${encodeURIComponent(obj.bucket_id)}/${obj.object_path}`,
    {
      method: 'POST',
      headers: {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ expiresIn: ttl }),
    }
  );
  if (!signRes.ok) {
    return errorResponse(502, 'SIGN_FAILED', 'Unable to mint signed storage URL');
  }
  const signed = await signRes.json();
  return jsonResponse(200, { signedUrl: signed.signedURL, expiresInSeconds: ttl });
});
