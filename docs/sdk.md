# Backend Hub JavaScript SDK (`@backend-hub/sdk`)

- **Current Immutable Version:** `0.1.0`
- **Built Browser Artifact:** `packages/sdk/dist/backend-hub-sdk-0.1.0.mjs`
- **Source Entrypoint:** [packages/sdk/src/index.js](../packages/sdk/src/index.js)

## Immutable Versioning & Pinning Policy

Static UI applications **must** pin an explicit immutable version (for example `/sdk/backend-hub-sdk-0.1.0.mjs` or a versioned SRI-hashed release tag). Never load production code from a mutable branch (`main`), `latest` alias, or unpinned URL.

To rebuild the immutable artifact after SDK source changes (after bumping `version` in `packages/sdk/package.json`):

```bash
npm run build:sdk
```

## Configuration (Fail Closed)

```js
import { createHubClient } from '/sdk/backend-hub-sdk-0.1.0.mjs';

const hub = createHubClient({
  environment: 'local',              // Required: 'local' | 'staging' | 'production'
  baseUrl: 'http://127.0.0.1:4000',  // Required: explicit URL (production requires https://)
  appId: 'notes-demo',               // Required: registered app slug (routing context only)
  timeoutMs: 8000,                   // Optional request timeout (ms)
  maxRetries: 2,                     // Optional retries for idempotent requests only
  storage: window.localStorage,      // Optional session store (defaults to in-memory)
});
```

Configuration validation fails closed (`ConfigError`) if:
- `environment` is missing or not `'local' | 'staging' | 'production'` (never silently falls back to `production`);
- `baseUrl` is missing, malformed, or uses `http://` when `environment === 'production'`;
- `appId` is invalid;
- privileged keys (`serviceKey`, `serviceRoleKey`, `jwtSecret`) are passed into client config.

> **Same-Origin Note:** Passing `window.localStorage` persists the user JWT under `hub:<environment>:<appId>:session`. Separate storage keys prevent accidental UX collisions, **not** security isolation—any script running on the same origin can read `localStorage`.

## API Surface

- `hub.health()` — `GET /health` readiness check.
- `hub.auth.signup(email, password)` / `login(email, password)` / `logout()` / `getUser()` / `getSession()` / `onAuthStateChange(cb)`.
- `hub.app.enroll()` — self-enrolls the authenticated user as `'member'` when the app has `allow_self_enroll = true`.
- `hub.app.refreshContext()` — exchanges user session for a short-lived server-signed app-context token (`x-app-context`).
- `hub.app.getCapabilities()` — fetches app limits, active membership, and usage summary.
- `hub.profile.get()` / `upsert({ displayName, bio, avatarPath, metadata })` / `delete()`.
- `hub.db(collection).list({ visibility, limit, order })` / `create({ title, payload, visibility })` / `update(id, patch)` / `remove(id)`.
- `hub.storage.list()` / `upload(bucketId, relativePath, fileOrBytes, { mimeType, idempotencyKey })` / `createSignedUrl(objectId, { expiresInSeconds })` / `remove(objectId)`.
- `hub.functions.invoke(name, payload, { idempotencyKey })`.

## Typed Errors, Timeouts, and Safe Retries

All failures throw subclasses of `HubError` (`packages/sdk/src/errors.js`):
- `ConfigError`, `ValidationError`, `AuthError` (`401`), `AuthorizationError` (`403`), `NotFoundError` (`404`), `QuotaError` (`413` / `429 QUOTA_EXCEEDED`), `RateLimitError` (`429 RATE_LIMITED`), `TimeoutError`, `NetworkError`.
- Timeouts abort via `AbortController` (`timeoutMs`, default `8000` ms).
- Retries run **only** on idempotent requests (`GET`, `HEAD`, or explicit `Idempotency-Key` / `idempotent: true`) for transient `502`/`503`/`504`, `TimeoutError`, or `NetworkError`. Auth (`401`/`403`), validation (`400`), and quota (`429 QUOTA_EXCEEDED`) errors are never retried automatically.

## Compatibility, Upgrades, and Rollback

- **Minor/Patch (`0.1.x` -> `0.1.y`):** Backward compatible with existing backend endpoints; apps update their pinned script path/tag explicitly.
- **Breaking (`0.x` -> `1.0`):** Use expand/migrate/contract on backend endpoints first, test staging apps with the new pinned SDK artifact, then promote.
- **Rollback:** Revert the static app's pinned SDK URL to the previous immutable artifact (e.g. `backend-hub-sdk-0.1.0.mjs`) and redeploy static assets.
