import crypto from 'node:crypto';

export const TOKEN_AUDIENCE = {
  USER: 'backend-hub:user',
  APP_CONTEXT: 'backend-hub:app-context',
  STORAGE_UPLOAD: 'backend-hub:storage-upload',
  STORAGE_DOWNLOAD: 'backend-hub:storage-download',
};

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };

function base64UrlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64url');
}

function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url');
}

export function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 256) {
    throw new Error('Password must be between 8 and 256 characters');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p
  });
  return `scrypt$${SCRYPT_PARAMS.N}$${SCRYPT_PARAMS.r}$${SCRYPT_PARAMS.p}$${salt}$${derived.toString('hex')}`;
}

export function verifyPassword(password, storedHash) {
  if (typeof password !== 'string' || typeof storedHash !== 'string') return false;
  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = parts[4];
  const expectedHex = parts[5];
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;

  const derived = crypto.scryptSync(password, salt, Buffer.from(expectedHex, 'hex').length, { N, r, p });
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export function signJwt(payload, secret, { issuer = 'backend-hub', audience, ttlSeconds = 900 } = {}) {
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('JWT signing secret must be at least 16 characters');
  }
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iss: issuer,
    ...(audience ? { aud: audience } : {}),
    iat: now,
    exp: now + ttlSeconds,
    jti: payload.jti ?? crypto.randomUUID()
  };
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(fullPayload));
  const signingInput = `${header}.${body}`;
  const sig = crypto.createHmac('sha256', secret).update(signingInput).digest();
  return `${signingInput}.${base64UrlEncode(sig)}`;
}

export function verifyJwt(token, secret, { issuer = 'backend-hub', audience } = {}) {
  if (typeof token !== 'string' || !secret) {
    return { ok: false, error: 'Missing token' };
  }
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { ok: false, error: 'Malformed JWT' };
  }

  const [headerB64, bodyB64, sigB64] = parts;
  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    payload = JSON.parse(base64UrlDecode(bodyB64).toString('utf8'));
  } catch {
    return { ok: false, error: 'Invalid JWT encoding' };
  }

  if (header.alg !== 'HS256' || header.typ !== 'JWT') {
    return { ok: false, error: 'Unsupported JWT header' };
  }

  const expectedSig = crypto.createHmac('sha256', secret).update(`${headerB64}.${bodyB64}`).digest();
  let actualSig;
  try {
    actualSig = base64UrlDecode(sigB64);
  } catch {
    return { ok: false, error: 'Invalid signature encoding' };
  }

  if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) {
    return { ok: false, error: 'Invalid JWT signature' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= now) {
    return { ok: false, error: 'Token expired' };
  }
  if (typeof payload.nbf === 'number' && payload.nbf > now) {
    return { ok: false, error: 'Token not yet active' };
  }
  if (issuer && payload.iss !== issuer) {
    return { ok: false, error: 'Invalid token issuer' };
  }
  if (audience && payload.aud !== audience) {
    return { ok: false, error: 'Invalid token audience' };
  }

  return { ok: true, payload };
}

export function timingSafeSecretEquals(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string' || !expected) {
    return false;
  }
  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

export function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function deriveSubkey(masterSecret, purpose) {
  return crypto.createHmac('sha256', masterSecret).update(`purpose:${purpose}`).digest('hex');
}
