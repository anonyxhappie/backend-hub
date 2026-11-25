import { jsonResponse } from '../_shared/errors.ts';

Deno.serve(async (req: Request) => {
  if (req.method !== 'GET') {
    return jsonResponse(405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Use GET', status: 405 } });
  }
  return jsonResponse(200, {
    status: 'ok',
    environment: Deno.env.get('HUB_ENV') ?? 'unconfigured',
    timestamp: new Date().toISOString(),
  });
});
