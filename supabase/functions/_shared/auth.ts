// Shared Deno/Edge helper for verifying user JWTs and minting short-lived app-context tokens.
// Server-only secrets (SUPABASE_SERVICE_ROLE_KEY, HUB_APP_CONTEXT_SECRET) are read from Deno.env
// and NEVER returned to browser clients.

export async function signHmacJwt(
  payload: Record<string, unknown>,
  secret: string,
  ttlSeconds: number,
  audience: string
): Promise<{ token: string; exp: number }> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSeconds;
  const fullPayload = {
    ...payload,
    iss: 'backend-hub',
    aud: audience,
    iat: now,
    exp,
    jti: crypto.randomUUID(),
  };

  const encode = (obj: unknown) =>
    btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const signingInput = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(fullPayload)}`;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return { token: `${signingInput}.${sigB64}`, exp };
}

export function requireEnv(name: string): string {
  const val = Deno.env.get(name);
  if (!val || val.trim().length === 0) {
    throw new Error(`Missing required server environment variable: ${name}`);
  }
  return val;
}
