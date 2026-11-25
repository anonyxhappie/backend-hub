# Environments, Migrations, and Release Controls

## Environment Separation

Backend Hub keeps `local`, `staging`, and `production` strictly isolated:

| Concern | Local (`HUB_ENV=local`) | Staging (`HUB_ENV=staging`) | Production (`HUB_ENV=production`) |
|---|---|---|---|
| Database | Embedded PGlite (`.local-hub/pgdata`) | Dedicated staging PostgreSQL/Supabase project | Dedicated production PostgreSQL/Supabase project |
| Credentials | Local dev-only defaults in `.local-hub` | Staging secret store (never production keys) | Production secret store (protected reviewers) |
| Seed data | `supabase/seed.sql` allowed | Synthetic test apps/users only; never production dumps | No dev seed; explicit reviewed app registrations |
| Origins / Previews | `http://127.0.0.1:4100` | Staging & isolated preview origins (`https://*.preview...`) | Explicit production HTTPS origins only |
| Config failure | Local defaults only when `HUB_ENV=local` | Fails closed if secrets/URLs missing | Fails closed if secrets missing or `http://` URL used |

**Preview builds** must always point to staging configuration and isolated preview origins. Never expose production secrets or production URLs in PR preview builds or CI logs.

## Database Migration Rules

1. **Ordered & Checksum-Verified:** Migrations in `supabase/migrations/` are numbered `0001_...`, `0002_...` and recorded in `hub_private.schema_migrations` with SHA-256 checksums.
2. **Stale & Tampered Run Rejection:** `applyMigrations()` refuses to modify already-applied migrations (checksum mismatch) and rejects out-of-order/stale migrations whose version precedes an already-applied migration.
3. **Expand / Migrate / Contract:** When old and new static UI versions may overlap during a rollout, add nullable columns/new endpoints first (expand), migrate callers, and drop legacy columns only in a later release (contract).
4. **No Destructive Auto-Rollback:** Never run automatic `DROP` rollbacks on production. Document forward-repair SQL or restore from a verified backup snapshot.

## CI vs. Future Deployment Automation Controls

The repository's current workflow ([.github/workflows/ci.yml](../.github/workflows/ci.yml)) runs **validation checks only** (SDK bundle drift, lint/secret scan, formatting, fresh + upgrade migration tests on disposable PGlite DBs, adversarial RLS/storage/quota tests, and E2E tests). It does **not** deploy, create Supabase projects, or touch cloud resources.

If deployment automation is added in the future, it **must** enforce:

1. **Serialized Staging Mutations:**
   - Use a repository-wide GitHub Actions concurrency group for staging migrations/deploys:
     ```yaml
     concurrency:
       group: staging-db-deploy
       cancel-in-progress: false
     ```
   - Never run two concurrent staging migration jobs against one shared staging database.
2. **Stale-Revision Guard:**
   - Before applying staging migrations, compare the checked-out git commit timestamp/sequence or migration head against the last recorded deployment revision so an older queued job cannot overwrite a newer state.
3. **Protected Production Approval Gate:**
   - Production deployments require a GitHub Protected Environment (`production`) with mandatory human reviewers, a reviewed migration plan, passing staging verification, current backup/restore verification, and explicit confirmation of the target project ref.
