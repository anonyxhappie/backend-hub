# Backend Hub Architecture

**Status:** Local & portable foundation implemented (`supabase/migrations/`, `server/`, `packages/sdk/`, `examples/notes-app/`, `tests/`). Hosted cloud resources remain unprovisioned.
**Scope:** Shared backend for a portfolio target of 10–20 independent static UI applications.

## Goals and constraints

- Give small static applications a reusable backend for identity, app-scoped profiles and records, files, and trusted server operations.
- Keep UI applications static and framework-agnostic. A shared JavaScript SDK is the preferred client interface.
- Target **$0 ongoing infrastructure cost, with no credit card required**, and verify each provider's current terms, limits, inactivity rules, and payment requirements before adopting or provisioning it. This is a goal and release constraint, not a vendor-tier promise. If a required capability cannot meet it, pause and choose a compliant alternative or seek an explicit product decision.
- Support a portfolio target of 10–20 applications without assuming that a free service plan can safely serve that load.
- Keep staging and production separate, including credentials, data, auth settings, storage, and application configuration.

## Proposed shape

The initial direction is a managed PostgreSQL backend with Supabase Auth, PostgreSQL Row Level Security (RLS), Storage, and Edge Functions, plus static hosting for the UIs. Provider choice and current no-cost eligibility remain subject to verification before any resource is created.

```text
Static UI (one registered app, preferably its own origin)
    | public project URL + public anon key; no privileged secrets
    v
Versioned Hub SDK -----> Auth / short-lived app-context broker
    |                                |
    +---- scoped data requests ------+
    |                                v
    +--------------------------> PostgreSQL + RLS
    +--------------------------> Storage policies
    +--------------------------> trusted Edge Functions
                                      |
                               server-only credentials
```

The browser SDK is convenience and API ergonomics, not a security boundary. Database, storage, and trusted function policies enforce authorization regardless of whether a caller uses the SDK.

## Identity, app context, and tenant authorization

Identity is shared across the portfolio unless a later decision changes it: a person may use one identity across apps. Authorization, profiles, records, files, and quotas are scoped to a registered app. A per-app browser storage key only separates local session persistence; it does not create a separate identity or authorization boundary.

A client-supplied `app_id`, URL parameter, SDK option, request body field, or Storage `storageKey` is **not proof** of app identity. Never grant access based on those values alone.

Before app-scoped access, a trusted authorization boundary must bind the authenticated user to a registered application and issue or establish a short-lived, cryptographically verifiable app context. RLS and storage policies consume only server-minted claims or an equivalent trusted server-side authorization result. The context includes app identity, subject, expiry, issuer/audience, and only the capabilities needed. It is not a service-role credential. Do not let the browser mint or modify trusted claims.

For static public clients, the browser cannot hold a secret. Where an app's configured origin is used to select its context, keep apps on distinct origins for any meaningful app isolation; validate the origin against a server-owned registry and still require user membership/capability checks. An origin or public app identifier is routing context, not a secret. If the selected provider cannot securely express this trust flow, route all sensitive access through a trusted function and do not claim direct app-level isolation until proven. Shared path-based apps on one origin are coupled: same-origin script can read browser storage and act with that origin's authority.

## Data model and authorization invariants

Keep the first schema small and explicit; introduce ancillary tables only when a real capability needs them.

- `apps`: immutable app identifier, status, registered origins, allowed collections, and configurable limits.
- `app_memberships`: composite key `(app_id, user_id)`, role, status, timestamps. Only trusted administrative operations can grant elevated roles.
- `app_profiles`: one profile per `(app_id, user_id)`.
- `app_records`: app identifier, owner identifier, collection, visibility, payload, timestamps. Validate collection against the app registry and use database constraints for required fields.
- Storage object names use a server-defined namespace that binds app and owner; path construction in the SDK is not authorization.
- Add audit/usage records as their enforcement and retention requirements become concrete.

Enable RLS on every exposed table and review grants and default privileges, views (including invoker behavior), RPC and `SECURITY DEFINER` functions (fixed safe `search_path`), foreign keys, uniqueness, and both `USING` and `WITH CHECK` for updates. Public visibility means publicly readable **within an explicitly defined app scope**; it never means cross-app access by default.

Policies must verify the trusted app context and the relevant membership/capability. Protect `app_id`, `owner_id`, membership role, and other tenant/identity fields from client updates using column grants, constraints, triggers, or trusted procedures. Ownership and tenant fields are immutable after creation except for a narrowly defined audited transfer operation. Treat security-linter output as one check, not proof. Maintain adversarial tests for cross-user, cross-app, anonymous, role escalation, update, delete, RPC, and storage cases before real apps depend on the platform.

## Storage

Use private buckets by default. Derive and validate the app and owner namespace from trusted authorization context; validate every path segment, app status, and membership server-side. Updates must not move an object into another app or owner's path. Signed URLs are bearer credentials: scope the object and use short expirations consistent with the feature.

The browser may check file size/type for a better experience, but enforce upload limits and allowed types at trusted server/policy boundaries. Enforce per-app and per-user quotas server-side with atomic reservations, reconciliation against actual objects, and safe handling of retries/deletes. Add malware scanning when the data and threat assessment justify it.

## SDK and application contract

The framework-agnostic SDK may expose `auth`, `profile`, `db(collection)`, `storage`, `functions`, `app` capability metadata, and `health`. Define typed errors, timeouts/retry behavior, and auth lifecycle behavior. Never expose service-role credentials or silently switch environments.

Publish immutable, versioned SDK releases. Applications pin an explicit version; never load production code from a mutable `main`, `latest`, or unpinned URL. Document compatibility, deprecation, rollback, and upgrade steps. Production configuration must be explicit and fail closed if missing.

## Environments, migrations, and releases

Staging and production are separate provider projects/environments with separate credentials and data. Preview builds use staging-only configuration and isolated preview origins. Do not place production secrets in preview builds or logs.

Migrations are reviewed, ordered, repeatable where practical, and tested from a clean database and against a representative prior schema. Use backward-compatible expand/migrate/contract changes when old and new clients may overlap. Do not rely on destructive automatic rollback; document forward repair or restore steps.

When deployment automation is introduced, serialize staging migrations and deployments with a repository-wide concurrency group, reject stale revisions before applying, and avoid concurrent mutation of one staging database. Migration validation should run independently. Complex tests should use disposable databases where practical. Production deploys require protected environment controls, explicit approval, a reviewed migration plan, and a tested recovery path. Staging must never overwrite or seed from production data.

## Quotas, monitoring, and recovery

Quotas are application policy, not provider free-tier limits. Establish configurable server-enforced limits for records, storage, individual uploads, requests/rate, function invocations, auth abuse, and public-download egress. Count and reserve usage on trusted services; reconcile it and define a clear response when a limit is reached.

Track database/storage/egress utilization, latency and errors, auth failures, function failures, migration results, quota denials, suspicious cross-tenant attempts, backup age, and restore checks. Define alerts and an owner/runbook before production use. Minimize sensitive log contents and set retention.

Document provider backup coverage, frequency, retention, recovery point and time objectives, and export portability. Backups are not proven until restore drills succeed. For every environment, keep a recoverable schema/data export where feasible, record restore steps, and test recovery before meaningful user data is stored. Free-tier backup and recovery capabilities must be verified; if they are insufficient for the data's importance, do not store that data there under a $0 requirement.

## Phased delivery

1. **Completed:** Verified Supabase Free Plan terms (`2026-11-25`, see [docs/operations-and-recovery.md](docs/operations-and-recovery.md)) and documented app-context trust limits ([ADR 0002](docs/adr/0002-app-context-and-local-runtime.md)).
2. **Completed:** Implemented ordered migrations (`0001`–`0005`), RLS, private storage & atomic quota reservations, local Hub runtime (`server/`), and adversarial security/migration tests (`tests/`).
3. **Completed:** Built immutable-versioned SDK (`packages/sdk/dist/backend-hub-sdk-0.1.0.mjs`), pinned from `examples/notes-app/`, and added non-deploying CI validation (`.github/workflows/ci.yml`).
4. **Future (before hosted production):** Provision separate staging/production projects, wire serialized staging migration workflow + protected production approvals ([docs/environments-and-releases.md](docs/environments-and-releases.md)), verify live hosted burst rate limits, and schedule external backup/restore drills.

This document reflects the implemented repository foundation; no cloud project, hosted database, or production deployment has been provisioned.
