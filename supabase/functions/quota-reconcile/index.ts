import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.1';
import { requireEnv } from '../_shared/auth.ts';
import { errorResponse, jsonResponse } from '../_shared/errors.ts';

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') {
    return errorResponse(405, 'METHOD_NOT_ALLOWED', 'Use POST');
  }

  const supabaseUrl = requireEnv('SUPABASE_URL');
  const serviceRoleKey = requireEnv('SUPABASE_SERVICE_ROLE_KEY');
  const authHeader = req.headers.get('authorization');

  if (authHeader !== `Bearer ${serviceRoleKey}`) {
    return errorResponse(403, 'FORBIDDEN', 'Service role authorization required.');
  }

  const body = await req.json().catch(() => ({}));
  const appId = typeof body?.appId === 'string' ? body.appId : null;

  const admin = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } });
  const { data, error } = await admin.rpc('reconcile_app_usage', { p_app_id: appId });
  if (error) {
    return errorResponse(500, 'RECONCILE_FAILED', error.message);
  }
  return jsonResponse(200, { reconciled: data });
});
