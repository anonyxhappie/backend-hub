# Operations, Quotas, Monitoring, and Recovery

## Verified Provider Terms & Cost Constraints ($0 / No Credit Card)

**Verification Date:** `2026-11-25` (checked against Supabase documentation and pricing terms via web search).

| Provider Feature | Verified Free Plan Limit (2026-11-25) | Impact on Backend Hub Portfolio (10–20 Apps) |
|---|---|---|
| Credit card required | **No** (Free Plan requires no card) | Meets no-card constraint for prototyping / low-traffic apps |
| Active free projects per org | **2 active projects** per organization | Staging + Production use both slots; **per-app separate Supabase projects beyond 2 are not free in one org** |
| Database size | **500 MB** per project | Shared across all 10–20 apps; requires strict `max_records_per_app` quotas & monitoring |
| File storage | **1 GB** total (50 MB max single upload) | Requires strict `max_storage_bytes` per app (e.g., 40–50 MB × 20 apps) |
| Bandwidth / Egress | **5 GB** outbound (+ 5 GB cached) / month | Signed downloads & public reads share one 5 GB monthly pool |
| Monthly Active Users (MAU) | **50,000** MAU | Shared portfolio identity pool |
| Edge Functions | **500,000** invocations / month | Includes `issue-app-context` & storage token calls |
| Inactivity pausing | **Paused after 7 consecutive days of inactivity** (retained up to 1 year) | **High operational risk** for low-traffic apps; API returns errors until manually resumed |
| Automated backups / PITR | **Not included** on Free Plan | Must run external logical exports (`pg_dump` / `exportLogicalBackup`) before storing important data |

### Unverified Assumptions (Verify Before Any Hosted Provisioning)
- Exact burst requests-per-second / concurrent connection limits for Supabase Auth, PostgREST, and Edge Functions under concurrent traffic from 10–20 apps (not verified against live load tests).
- Static UI hosting provider limits (e.g., Cloudflare Pages, GitHub Pages, or Netlify bandwidth, build minutes, and commercial-use terms) — must be checked when selecting static hosting.
- **No-Go Trigger:** If 10–20 active apps exceed 500 MB DB, 1 GB storage, 5 GB egress, or require automated backups / zero-pause uptime without payment, **do not** store critical user data on the Free Plan—either reduce scope, self-host, or seek an explicit budget decision.

## Server-Enforced Quotas & Exhaustion Behavior

Quotas are enforced in PostgreSQL (`apps` table) and trusted functions—never solely in browser UI:
- **Records:** `max_records_per_app` and `max_records_per_user` enforced atomically via `pg_advisory_xact_lock` in `hub_auth.enforce_record_invariants()`. Returns `429 QUOTA_EXCEEDED` (`QuotaError`).
- **Storage:** `max_storage_bytes`, `max_user_storage_bytes`, and `max_upload_bytes` enforced atomically via `hub_private.reserve_storage_upload()` and verified against actual received byte length in `PUT /storage/v1/object/upload`. Returns `429 QUOTA_EXCEEDED` or `413 UPLOAD_TOO_LARGE`.
- **Rate Limits:** `rate_limit_rpm` enforced per app sliding window. Returns `429 RATE_LIMITED` with `Retry-After`.
- **Reconciliation:** `POST /functions/v1/quota-reconcile` (or `npm run reconcile`) expires stale `quota_reservations`, marks abandoned pending objects `deleted`, and recomputes `app_usage` from actual active rows.

## Monitoring & Alerting Baseline

Before onboarding real users to a hosted environment, configure collection and ownership for:
1. **Capacity Utilization:** DB size vs 500 MB, storage bytes vs 1 GB, monthly egress vs 5 GB -> alert at **70% warning**, **85% critical**.
2. **Error & Latency SLOs:** HTTP 5xx rate > 1% or p95 latency > 1s over 5 minutes; Edge Function failure rate > 2%.
3. **Security Signals (`audit_events`):** spikes in `auth.login` denials, `origin_not_allowed` denials, `no_active_membership` attempts, or `QUOTA_EXCEEDED` bursts.
4. **Backup Freshness & Restore Checks:** alert if latest verified export is > 24 hours old or last restore drill is > 30 days old.
5. **Log Hygiene:** never log passwords, `accessToken`, `appContextToken`, `serviceRoleKey`, or signed URL `?token=` query strings.

## Backups, RPO/RTO, and Restore Drills

- **RPO / RTO (Local / Free-Tier Export Model):**
  - Target RPO: **24 hours** (daily scheduled logical export outside the primary DB); target RTO: **1 hour** (provision/reset target DB, apply ordered migrations, restore export, run `reconcile`).
  - Note: Because Supabase Free Plan includes **zero automated backups**, RPO is strictly bounded by how often external exports run.
- **Local Export & Restore Drill (Verified in `tests/migrations.test.js`):**
  ```bash
  # Export logical snapshot
  node server/cli.js backup .local-hub/backup.json

  # Restore onto a clean/target database and reconcile usage
  HUB_DATA_DIR=.local-hub/restore-drill-pg node server/cli.js restore .local-hub/backup.json
  ```
- For hosted PostgreSQL / Supabase, use `pg_dump --schema=public --schema=auth` (or managed backups on paid plans) + storage bucket object sync, and rehearse restoring into a disposable staging database before declaring backups valid.
