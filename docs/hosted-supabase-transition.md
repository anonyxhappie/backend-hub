# Transitioning from Local Runtime to Hosted Supabase

This guide outlines the exact steps and configuration changes required to move Backend Hub from the local PGlite/Node runtime ([server/](../server/)) to hosted Supabase (**Auth**, **PostgreSQL Database**, **Storage**, and **Edge Functions**) while preserving the `$0` / no-credit-card constraint and all tenant isolation invariants.

> **Important:** No Supabase projects or secrets are provisioned in this repository. Remember that the Supabase Free Plan allows **2 active projects per organization** (consumed by `staging` + `production`), pauses after **7 days of inactivity**, and provides **no automated backups** ([operations-and-recovery.md](operations-and-recovery.md)).

## 1. Provision Separate Staging & Production Projects

1. Create two separate Supabase projects (no credit card required on Free Plan):
   - `backend-hub-staging`
   - `backend-hub-production` (only when ready for protected release review)
2. Keep project URLs, anon keys, `SUPABASE_SERVICE_ROLE_KEY`, and `HUB_APP_CTX_SECRET` strictly isolated between staging and production.

## 2. Database Migrations (`supabase/migrations/0001`–`0005`)

- Migration `0001_core_extensions_and_auth_helpers.sql` guards `auth.users` creation with `IF to_regclass('auth.users') IS NULL`, so hosted Supabase's GoTrue-owned `auth.users` table is preserved without ownership errors.
- Link and push migrations to **staging first** (never run `supabase/seed.sql` in production):
  ```bash
  supabase link --project-ref <STAGING_PROJECT_REF>
  supabase db push
  ```
- Register your production/staging apps and private buckets in `public.apps` and `public.storage_buckets` via a reviewed SQL migration or admin script using HTTPS origins (not `127.0.0.1`).

## 3. Authentication & Trusted App-Context Binding

- **Hosted Auth:** Replace local `/auth/v1/signup` & `/auth/v1/login` endpoints with Supabase Auth (`@supabase/supabase-js` or Supabase `/auth/v1/token` REST calls). Configure **Site URL** and **Redirect URLs** per environment in Supabase Auth settings.
- **App-Context Enforcement (Critical Trust Boundary):**
  - Do **not** expose raw PostgREST (`/rest/v1/*`) with only a standard Supabase user JWT unless `hub_auth.current_app_id()` is populated from a server-verified claim (`app_ctx_verified = 'true'`).
  - Either:
    1. Route app-scoped data access through Supabase Edge Functions (validating the user JWT + `x-app-context` signed by `issue-app-context` before querying Postgres with verified claims), **or**
    2. Use a Supabase Custom Access Token Auth Hook / short-lived scoped JWT minted by `issue-app-context` so PostgreSQL `request.jwt.claims` carries server-verified `app_id`, `app_caps`, `app_ctx_verified`, and `app_ctx_exp`.

## 4. Hosted Supabase Storage Wiring

- Create private buckets (`public = false`) matching `public.storage_buckets` (e.g., `notes-files`, `habits-files`).
- Complete the hosted Supabase Storage integration in [supabase/functions/storage-upload-intent/index.ts](../supabase/functions/storage-upload-intent/index.ts) and [storage-signed-url/index.ts](../supabase/functions/storage-signed-url/index.ts):
  1. Verify both the user JWT and `x-app-context` token (`HUB_APP_CTX_SECRET`).
  2. Call `hub_private.reserve_storage_upload(...)` via `service_role` to reserve quota atomically.
  3. Issue a Supabase Storage `createSignedUploadUrl(object_path)` and after upload verify object size/MIME and call `hub_private.commit_storage_upload(...)`.
  4. Replace local `/storage/v1/object/sign` downloads with Supabase Storage `createSignedUrl(object_path, ttlSeconds)` (60s–300s TTL).
- Add matching `storage.objects` RLS policies in Supabase denying direct client `INSERT`/`UPDATE`/`DELETE` and scoping `SELECT` to verified `(app_id, owner_id)`.

## 5. Edge Functions, Secrets & SDK Configuration

1. Set Edge Function secrets per environment (`supabase secrets set --project-ref <REF>`):
   - `HUB_APP_CTX_SECRET` (32+ random bytes, distinct per environment)
   - `HUB_STORAGE_SECRET` (32+ random bytes, distinct per environment)
   - `HUB_ENV` (`staging` or `production`)
   - (`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected by Supabase Edge Runtime; never expose `SUPABASE_SERVICE_ROLE_KEY` to static UIs.)
2. Deploy Edge Functions (`supabase functions deploy ... --project-ref <STAGING_PROJECT_REF>`).
3. Update [examples/portfolio-config.js](../examples/portfolio-config.js) (or inject at static build time) with explicit `staging` and `production` `https://` URLs, and deploy each static app (`notes-app`, `habits-app`, `hub-dashboard`) to **separate origins** (e.g., separate subdomains/projects on Cloudflare Pages, GitHub Pages, or Netlify).
4. Set up external scheduled logical backups (`pg_dump`) and `quota-reconcile` runs before storing important user data.
