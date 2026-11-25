# ADR 0002: Server-Minted App Context, Static Client Limits, and Local PostgreSQL Runtime

- **Status:** Accepted
- **Date:** 2026-11-25
- **Supersedes / Extends:** [ADR 0001](0001-shared-multi-tenant-backend.md)

## Context

Static UI applications run entirely in the user's browser and cannot hold a confidential client secret. An attacker can inspect bundled JavaScript, replay HTTP requests via `curl`, modify `localStorage`, or send arbitrary `app_id`, `Origin`, or `storageKey` values.

We also need a zero-cost, no-credit-card local development and CI workflow that executes **real PostgreSQL RLS, triggers, constraints, roles, and advisory locks** without requiring hosted cloud accounts or Docker images on every developer machine.

## Decision

1. **Server-Minted Short-Lived App Context (`app_ctx`)**:
   - Callers authenticate via user session JWT (`aud: backend-hub:user`) and request an app-context token from `POST /functions/v1/issue-app-context` with `{ appId }`.
   - The server verifies:
     1. `apps.status = 'active'` in the database registry;
     2. if an HTTP `Origin` header is present and `apps.allowed_origins` is non-empty, `Origin` is in `apps.allowed_origins`;
     3. for authenticated callers, an `'active'` row exists in `app_memberships` for `(app_id, user_id)`;
     4. for unauthenticated (`anon`) callers, `apps.allow_public_read = true` (issuing only `records:read_public`).
   - The server mints a 5-minute HS256 JWT (`aud: backend-hub:app-context`) bound to `sub`, `app_id`, `app_role`, `app_caps`, and `jti`.
   - On every `/rest/v1/*` request, the gateway verifies both tokens (including `app_ctx.sub === user.sub`), sets `request.jwt.claims` inside a PostgreSQL transaction with `SET LOCAL ROLE anon|authenticated`, and sets `app_ctx_verified = 'true'`.
   - PostgreSQL `hub_auth.current_app_id()` returns `NULL` unless `app_ctx_verified = 'true'` and `app_ctx_exp > now()`, causing RLS to fail closed if app context is omitted or forged.

2. **Honest Limits of Static-Client Isolation**:
   - `Origin` checks and CORS block *unprivileged cross-origin browser scripts* (e.g., an unrelated website calling the API from a user's browser).
   - `Origin` is **NOT** proof of client identity against non-browser tools (`curl`, Node scripts), nor does it protect against same-origin XSS if multiple apps share an origin.
   - If a single user holds active memberships in both `app-a` and `app-b`, a non-browser script holding that user's credentials can request `app_ctx` for either app. What the model **does** enforce is:
     - no access to apps where the user lacks an active membership;
     - no cross-app reads/writes using `app-a`'s token or client-supplied `app_id`/`owner_id` parameters;
     - no role escalation or immutable-field tampering.
   - For stronger app-level isolation (e.g., separating high-sensitivity apps or browser sessions), deploy apps on **separate origins** and/or **separate backend projects**.

3. **Local PGlite Runtime Parity**:
   - Local dev and CI run the exact same SQL migrations (`supabase/migrations/0001..0005.sql`) inside `@electric-sql/pglite` (embedded WebAssembly PostgreSQL) with genuine `anon`, `authenticated`, and `service_role` roles, `FORCE ROW LEVEL SECURITY`, triggers, and `pg_advisory_xact_lock`.

## Consequences

- Security invariants are verified on every `npm test` run in seconds at `$0` cost with zero cloud provisioning.
- Any hosted Supabase deployment must implement the same gateway/claim binding (or route sensitive multi-app reads/writes through trusted Edge Functions if PostgREST uses standard user-only JWTs without custom `app_id` claims).
