# Backend Hub

A reusable, security-first multi-tenant backend foundation, framework-agnostic JavaScript SDK (`@backend-hub/sdk`), and example static application for a portfolio of 10–20 static UI apps.

> **Status & Cost Constraint Notice:** This repository provides a working local PostgreSQL-backed implementation (via PGlite), Supabase-compatible SQL migrations, Supabase Edge Function definitions, an immutable-versioned SDK (`0.1.0`), a runnable example static app, and adversarial security tests. **No cloud/Supabase projects, secrets, or production deployments have been provisioned.** The `$0` / no-credit-card objective is treated as a hard constraint—see [docs/operations-and-recovery.md](docs/operations-and-recovery.md) for verified Free Plan limits and remaining unverified assumptions.

## What Is Included

- **Ordered PostgreSQL Migrations** ([supabase/migrations/](supabase/migrations/)):
  - `0001_core_extensions_and_auth_helpers.sql` — `hub_auth` / `hub_private` schemas, roles (`anon`, `authenticated`, `service_role`), `hub_auth.current_app_id()` fail-closed claim verification.
  - `0002_apps_and_memberships.sql` — `apps` registry, `app_memberships`, immutable role/status guards, `hub_self_enroll` RPC, RLS policies.
  - `0003_profiles_and_records.sql` — `app_profiles` and `app_records` with collection validation, immutable `app_id`/`owner_id`, column grants, and atomic record quota enforcement.
  - `0004_storage_and_quotas.sql` — private-by-default `storage_buckets`, path-validated `storage_objects`, `quota_reservations`, `app_usage`, and `hub_private.reserve_storage_upload` / `commit_storage_upload` / `reconcile_app_usage`.
  - `0005_audit_and_views.sql` — `audit_events` and `security_invoker = true` views (`app_member_summary`, `hub_record_stats`).
- **Local & Portable Backend Hub Server** ([server/](server/)) — Node.js HTTP runtime backed by real PostgreSQL (embedded PGlite) enforcing `SET LOCAL ROLE` + `request.jwt.claims` on every REST/RLS call, short-lived signed App Context tokens, private disk storage with signed URLs, and per-app rate limits.
- **Supabase Edge Functions** ([supabase/functions/](supabase/functions/)) — Deno/TypeScript reference handlers (`health`, `issue-app-context`, `storage-upload-intent`, `storage-signed-url`, `quota-reconcile`); `issue-app-context`, `health`, and `quota-reconcile` wire directly to PostgREST, while `storage-upload-intent` and `storage-signed-url` document the hosted Supabase Storage/RPC wiring alongside the full runnable implementation in [server/](server/).
- **Framework-Agnostic SDK** ([packages/sdk/](packages/sdk/)) — Zero-dependency ESM client with fail-closed environment config, typed errors, timeouts, safe idempotent retries, and immutable versioned bundle (`packages/sdk/dist/backend-hub-sdk-0.1.0.mjs`).
- **Example Static Apps & Portfolio Dashboard** ([examples/notes-app/](examples/notes-app/), [examples/habits-app/](examples/habits-app/), [examples/hub-dashboard/](examples/hub-dashboard/), & [examples/portfolio-config.js](examples/portfolio-config.js)) — Demonstrates signup/login, app enrollment, app-scoped profiles, private/app/public records, private file upload/signed download, per-app health checks, and a unified multi-app portfolio dashboard.
- **Adversarial & Migration Test Suite** ([tests/](tests/)) — Direct API bypass tests, cross-user/cross-app isolation, role escalation, storage path traversal, concurrent quota races, backup/restore drills, and SDK E2E tests.

## Quick Start (Local Development — $0, No Docker/Cloud Account Required)

Prerequisites: Node.js `>= 22` and `npm`.

```bash
# 1. Install dependencies (@electric-sql/pglite)
npm install

# 2. Build the immutable SDK bundle (packages/sdk/dist/backend-hub-sdk-0.1.0.mjs)
npm run build:sdk

# 3. Run ordered database migrations and non-production local seed (notes-demo, habits-demo)
npm run migrate
npm run seed

# 4. Start the local Backend Hub API (:4000) + Notes UI (:4100) + Habits UI (:4101) + Portfolio Dashboard (:4102)
npm run dev
```

Open any of the isolated local origins in your browser:
- **Notes Demo (`notes-demo`):** `http://127.0.0.1:4100` (allows self-enrollment and app-scoped public reads)
- **Habits Tracker (`habits-demo`):** `http://127.0.0.1:4101` (private-only, admin/pre-enrolled membership required)
- **Portfolio Dashboard:** `http://127.0.0.1:4102` (per-app health probes, usage vs quotas, and reconcile actions across your enrolled apps)
1. Check the **Backend Status** pill in the top right.
2. Sign up with an email and password (`>= 8` characters); the app signs up and enrolls your account as a `member` in `notes-demo`.
3. Update your app-scoped profile, create `private` / `app` / `public` notes, upload a private attachment (`.txt`, `.md`, `.json`, `.png`, `.jpg`, `.pdf`), open a short-lived signed download link, and run the trusted note summary function.

## Running Verification & Maintenance Commands

```bash
# Full CI check suite (SDK build, lint/secret scan, format check, migrations, adversarial security, E2E)
npm run ci

# Individual suites
npm run test:migrations
npm run test:security
npm run test:e2e

# Operational CLI commands
npm run reconcile
node server/cli.js backup .local-hub/backup.json
node server/cli.js restore .local-hub/backup.json
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture, trust boundaries, and baseline invariants.
- [SECURITY_THREAT_MODEL.md](SECURITY_THREAT_MODEL.md) — Threats, controls, verification status, and residual risks.
- [AGENT_PLAYBOOK.md](AGENT_PLAYBOOK.md) — Contributor and coding-agent security/release checklist.
- [docs/adr/0001-shared-multi-tenant-backend.md](docs/adr/0001-shared-multi-tenant-backend.md) — Initial shared multi-tenant backend ADR.
- [docs/adr/0002-app-context-and-local-runtime.md](docs/adr/0002-app-context-and-local-runtime.md) — App-context trust boundary limits and local runtime parity.
- [docs/sdk.md](docs/sdk.md) — SDK API contract, typed errors, immutable versioning, and upgrade/rollback guide.
- [docs/environments-and-releases.md](docs/environments-and-releases.md) — Local/staging/production isolation, serialized migrations, stale-run protection, and production approval gates.
- [docs/hosted-supabase-transition.md](docs/hosted-supabase-transition.md) — Step-by-step transition from the local runtime to hosted Supabase Auth, Database, Storage, and Edge Functions.
- [docs/operations-and-recovery.md](docs/operations-and-recovery.md) — Monitoring, alerts, quota exhaustion, backups/RPO/RTO, restore drills, and verified Supabase Free Plan terms.
