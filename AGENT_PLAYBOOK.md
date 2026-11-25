# Agent Playbook

A practical workflow for contributors and coding agents working on Backend Hub.

## Before changing code or design

1. Read [AGENTS.md](AGENTS.md) and [ARCHITECTURE.md](ARCHITECTURE.md).
2. Identify whether the change affects identity, app context, RLS, storage, migrations, SDK contracts, environments, quotas, or recovery.
3. State assumptions and inspect existing policies/tests before editing. Keep client convenience separate from enforceable authorization.
4. For a provider or cost decision, verify current plan terms, account eligibility, card requirements, quotas, suspension/inactivity behavior, backup/restore support, and expected portfolio load. Record the verification date and source. Do not promise free capacity based on old figures.

## Security review checklist

- Can an API caller change `app_id`, object path, role, owner, or tenant fields to access or mutate another app's data?
- Does the request carry a short-lived, server-verified app context? Where and how is it issued, bound, expired, and revoked?
- Does authorization also check user membership and capability? Is app status checked?
- Do table policies cover read/insert/update/delete, with both update `USING` and `WITH CHECK`? Are grants, views, RPCs, functions, triggers, and default privileges reviewed?
- Are app ID, owner ID, roles, and other security fields immutable for normal clients?
- Do Storage policies validate all path segments and prohibit cross-tenant moves? Are signed URLs private, short-lived bearer tokens?
- Are limits enforced on trusted services, including atomic quota reservations and reconciliation?
- Could XSS on a sibling app read browser storage, abuse shared origin capabilities, or reuse session state? Is a separate origin needed?
- Are privileged credentials absent from client bundles and logs?
- Are tests adversarial, including direct API requests that bypass the SDK?

## Database and migration workflow

- Keep migrations ordered, reviewed, and safe for expected old/new client overlap.
- Validate a fresh install and upgrade from the supported previous schema.
- Prefer expand/migrate/contract. Avoid destructive changes until consumers have moved and recovery is documented.
- Make migration validation independent of shared staging mutation.
- Serialize migrations/deployments that mutate staging. Reject stale revisions and ensure a stale run cannot overwrite newer state.
- Use disposable databases for concurrency-heavy integration tests when practical.
- Do not run staging steps with production credentials. Staging data must not be copied from production by default.

## SDK and static app workflow

- Keep SDK APIs framework-agnostic and publish explicit immutable versions.
- Pin apps to a version; document compatibility and migration/rollback guidance.
- Make environment selection explicit. Missing configuration must fail closed; no silent production fallback.
- Keep frontend validation for user feedback only. Repeat every security-critical check on the server.
- Static UI applications must use only public client credentials.

## Environments, cost, and operations

- Keep staging and production separate in provider projects, secrets, auth configuration, storage, and data.
- Preview URLs use staging settings and isolated origins. Never expose production keys in preview.
- Treat the $0/no-card target as a go/no-go constraint. If a required feature needs payment details or paid usage, pause and document alternatives; do not provision it under this goal.
- Use configurable application quotas. Do not equate an app's quota with provider plan capacity.
- Before production use, define monitoring, alert ownership, incident steps, backup coverage, retention, RPO/RTO, export, and a tested restore procedure.
- Backups are unverified until a restore drill succeeds. Report gaps plainly.

## Release readiness

Before any production release, the responsible maintainer reviews:

- RLS, Storage, grants, functions, immutable fields, and adversarial test results.
- Migration ordering, concurrency controls, stale-run handling, and recovery steps.
- SDK version, consumer compatibility, environment pinning, and rollback route.
- Current cost/card/limit assumptions and server-side quota enforcement.
- Monitoring, alert ownership, backup age, and restore-test evidence.
- Protected production approval and exact target environment.

This repository currently contains architecture documentation only. Do not infer that any service, workflow, project, secret, or deployment has been provisioned.
