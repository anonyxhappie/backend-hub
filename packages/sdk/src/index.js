import {
  ConfigError,
  AuthError,
  ValidationError,
} from './errors.js';
import { requestWithRetry } from './http.js';

export const SDK_VERSION = '0.1.0';

const ALLOWED_ENVIRONMENTS = new Set(['local', 'staging', 'production']);
const APP_ID_RE = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/;
const COLLECTION_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

function createMemoryStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, String(v)),
    removeItem: (k) => map.delete(k),
  };
}

function validateConfig(config) {
  if (!config || typeof config !== 'object') {
    throw new ConfigError('Backend Hub SDK configuration object is required.');
  }
  if ('serviceKey' in config || 'serviceRoleKey' in config || 'jwtSecret' in config) {
    throw new ConfigError('Privileged credentials must never be passed to the browser SDK.');
  }
  if (!ALLOWED_ENVIRONMENTS.has(config.environment)) {
    throw new ConfigError(
      `Explicit environment ("local" | "staging" | "production") is required; got "${config.environment ?? ''}".`
    );
  }
  if (typeof config.baseUrl !== 'string' || !config.baseUrl.trim()) {
    throw new ConfigError('Explicit baseUrl is required; SDK never falls back to a default production URL.');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(config.baseUrl);
  } catch {
    throw new ConfigError(`Invalid baseUrl: "${config.baseUrl}"`);
  }

  if (config.environment === 'production' && parsedUrl.protocol !== 'https:') {
    throw new ConfigError('Production environment requires an https:// baseUrl.');
  }
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new ConfigError(`Unsupported baseUrl protocol: "${parsedUrl.protocol}"`);
  }

  if (typeof config.appId !== 'string' || !APP_ID_RE.test(config.appId)) {
    throw new ConfigError(`Invalid appId: "${config.appId ?? ''}"`);
  }

  return {
    environment: config.environment,
    baseUrl: parsedUrl.origin + parsedUrl.pathname.replace(/\/+$/, ''),
    appId: config.appId,
    timeoutMs: Number.isFinite(config.timeoutMs) ? config.timeoutMs : 8000,
    maxRetries: Number.isInteger(config.maxRetries) ? config.maxRetries : 2,
    fetchImpl: config.fetchImpl ?? globalThis.fetch?.bind(globalThis),
    storage: config.storage ?? createMemoryStorage(),
  };
}

/**
 * Creates an explicit, fail-closed Backend Hub SDK client.
 * Note: Browser SDK configuration and appId are convenience/routing parameters,
 * never a security boundary. All tenancy and authorization rules are enforced by the backend.
 */
export function createHubClient(rawConfig) {
  const cfg = validateConfig(rawConfig);
  if (typeof cfg.fetchImpl !== 'function') {
    throw new ConfigError('A fetch implementation is required.');
  }

  const sessionKey = `hub:${cfg.environment}:${cfg.appId}:session`;
  const listeners = new Set();

  let session = null;
  try {
    const rawSaved = cfg.storage.getItem(sessionKey);
    if (rawSaved) session = JSON.parse(rawSaved);
  } catch {
    session = null;
  }

  let appContext = null;

  function persistSession(nextSession) {
    session = nextSession;
    appContext = null;
    if (nextSession) {
      cfg.storage.setItem(sessionKey, JSON.stringify(nextSession));
    } else {
      cfg.storage.removeItem(sessionKey);
    }
    for (const cb of listeners) {
      try {
        cb(session);
      } catch {
        // Ignore subscriber errors
      }
    }
  }

  function request(path, options = {}) {
    const headers = { ...(options.headers ?? {}) };
    if (session?.accessToken && !headers.Authorization) {
      headers.Authorization = `Bearer ${session.accessToken}`;
    }
    return requestWithRetry(cfg.fetchImpl, `${cfg.baseUrl}${path}`, {
      timeoutMs: cfg.timeoutMs,
      maxRetries: cfg.maxRetries,
      ...options,
      headers,
    });
  }

  async function ensureAppContext({ forceRefresh = false } = {}) {
    const now = Math.floor(Date.now() / 1000);
    if (!forceRefresh && appContext && appContext.expiresAt > now + 15) {
      return appContext;
    }
    const issued = await request('/functions/v1/issue-app-context', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appId: cfg.appId }),
      idempotent: true,
    });
    appContext = issued;
    return appContext;
  }

  async function scopedRequest(path, options = {}) {
    const ctx = await ensureAppContext();
    const headers = {
      ...(options.headers ?? {}),
      'x-app-context': ctx.appContextToken,
    };
    return request(path, { ...options, headers });
  }

  function requireUserSession() {
    if (!session?.accessToken || !session?.user?.id) {
      throw new AuthError('No active user session. Sign in first.');
    }
    return session;
  }

  return {
    version: SDK_VERSION,
    environment: cfg.environment,
    appId: cfg.appId,

    auth: {
      async signup(email, password) {
        const res = await request('/auth/v1/signup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        persistSession({ accessToken: res.accessToken, expiresAt: res.expiresAt, user: res.user });
        return res.user;
      },

      async login(email, password) {
        const res = await request('/auth/v1/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        persistSession({ accessToken: res.accessToken, expiresAt: res.expiresAt, user: res.user });
        return res.user;
      },

      logout() {
        persistSession(null);
      },

      async getUser() {
        requireUserSession();
        const res = await request('/auth/v1/user', { method: 'GET' });
        return res.user;
      },

      getSession() {
        return session;
      },

      onAuthStateChange(callback) {
        listeners.add(callback);
        return () => listeners.delete(callback);
      },
    },

    app: {
      async enroll() {
        requireUserSession();
        const res = await request('/functions/v1/enroll', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ appId: cfg.appId }),
        });
        appContext = null;
        return res.membership;
      },

      async refreshContext() {
        return ensureAppContext({ forceRefresh: true });
      },

      async getCapabilities() {
        return scopedRequest('/functions/v1/app-capabilities', { method: 'GET' });
      },
    },

    profile: {
      async get() {
        const s = requireUserSession();
        const rows = await scopedRequest(
          `/rest/v1/app_profiles?user_id=eq.${encodeURIComponent(s.user.id)}&limit=1`,
          { method: 'GET' }
        );
        return rows[0] ?? null;
      },

      async upsert({ displayName, bio = '', avatarPath = null, metadata = {} }) {
        const s = requireUserSession();
        const existing = await this.get();
        if (existing) {
          const updated = await scopedRequest(
            `/rest/v1/app_profiles?user_id=eq.${encodeURIComponent(s.user.id)}`,
            {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                display_name: displayName,
                bio,
                avatar_path: avatarPath,
                metadata,
              }),
            }
          );
          return updated[0];
        }
        return scopedRequest('/rest/v1/app_profiles', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            app_id: cfg.appId,
            user_id: s.user.id,
            display_name: displayName,
            bio,
            avatar_path: avatarPath,
            metadata,
          }),
        });
      },

      async delete() {
        const s = requireUserSession();
        const rows = await scopedRequest(
          `/rest/v1/app_profiles?user_id=eq.${encodeURIComponent(s.user.id)}`,
          { method: 'DELETE' }
        );
        return rows[0] ?? null;
      },
    },

    db(collection) {
      if (typeof collection !== 'string' || !COLLECTION_RE.test(collection)) {
        throw new ValidationError(`Invalid collection name: "${collection}"`);
      }

      return {
        async list({ visibility, limit = 50, order = 'created_at.desc' } = {}) {
          const params = new URLSearchParams({
            collection: `eq.${collection}`,
            limit: String(limit),
            order,
          });
          if (visibility) params.set('visibility', `eq.${visibility}`);
          return scopedRequest(`/rest/v1/app_records?${params.toString()}`, { method: 'GET' });
        },

        async create({ title, payload = {}, visibility = 'private' }) {
          const s = requireUserSession();
          return scopedRequest('/rest/v1/app_records', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              app_id: cfg.appId,
              owner_id: s.user.id,
              collection,
              visibility,
              title,
              payload,
            }),
          });
        },

        async update(recordId, { title, payload, visibility }) {
          requireUserSession();
          if (!recordId) throw new ValidationError('recordId is required.');
          const patch = {};
          if (title !== undefined) patch.title = title;
          if (payload !== undefined) patch.payload = payload;
          if (visibility !== undefined) patch.visibility = visibility;

          const rows = await scopedRequest(
            `/rest/v1/app_records?id=eq.${encodeURIComponent(recordId)}&collection=eq.${encodeURIComponent(collection)}`,
            {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(patch),
            }
          );
          return rows[0];
        },

        async remove(recordId) {
          requireUserSession();
          if (!recordId) throw new ValidationError('recordId is required.');
          const rows = await scopedRequest(
            `/rest/v1/app_records?id=eq.${encodeURIComponent(recordId)}&collection=eq.${encodeURIComponent(collection)}`,
            { method: 'DELETE' }
          );
          return rows[0];
        },
      };
    },

    storage: {
      async list() {
        requireUserSession();
        return scopedRequest('/rest/v1/storage_objects?order=created_at.desc&limit=100', {
          method: 'GET',
        });
      },

      async upload(bucketId, relativePath, fileOrBytes, { mimeType, idempotencyKey } = {}) {
        requireUserSession();
        let bytes;
        let resolvedMime = mimeType;
        if (typeof Blob !== 'undefined' && fileOrBytes instanceof Blob) {
          bytes = new Uint8Array(await fileOrBytes.arrayBuffer());
          resolvedMime = resolvedMime || fileOrBytes.type || 'application/octet-stream';
        } else if (fileOrBytes instanceof Uint8Array || ArrayBuffer.isView(fileOrBytes)) {
          bytes = new Uint8Array(fileOrBytes.buffer, fileOrBytes.byteOffset, fileOrBytes.byteLength);
        } else if (typeof fileOrBytes === 'string') {
          bytes = new TextEncoder().encode(fileOrBytes);
          resolvedMime = resolvedMime || 'text/plain';
        } else {
          throw new ValidationError('fileOrBytes must be a File/Blob, Uint8Array, or string.');
        }

        const idem = idempotencyKey ?? globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
        const intent = await scopedRequest('/functions/v1/storage-upload-intent', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': idem,
          },
          body: JSON.stringify({
            bucketId,
            relativePath,
            mimeType: resolvedMime,
            sizeBytes: bytes.byteLength,
          }),
          idempotent: true,
        });

        const committed = await request(
          `/storage/v1/object/upload?token=${encodeURIComponent(intent.uploadToken)}`,
          {
            method: 'PUT',
            headers: { 'Content-Type': resolvedMime },
            body: bytes,
            idempotent: false,
          }
        );
        return committed.object;
      },

      async createSignedUrl(objectId, { expiresInSeconds = 60 } = {}) {
        requireUserSession();
        const res = await scopedRequest('/functions/v1/storage-signed-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ objectId, expiresInSeconds }),
          idempotent: true,
        });
        return {
          url: `${cfg.baseUrl}${res.signedUrl}`,
          expiresAt: res.expiresAt,
        };
      },

      async remove(objectId) {
        requireUserSession();
        return scopedRequest(
          `/functions/v1/storage-object?objectId=${encodeURIComponent(objectId)}`,
          { method: 'DELETE' }
        );
      },
    },

    functions: {
      async invoke(name, payload = {}, { idempotencyKey } = {}) {
        if (!/^[a-z0-9-]+$/.test(name)) {
          throw new ValidationError(`Invalid function name: "${name}"`);
        }
        const headers = { 'Content-Type': 'application/json' };
        if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
        return scopedRequest(`/functions/v1/${name}`, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
          idempotent: Boolean(idempotencyKey),
        });
      },
    },

    async health() {
      return request('/functions/v1/health', { method: 'GET' });
    },
  };
}
