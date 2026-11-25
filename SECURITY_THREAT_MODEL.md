# Security Threat Model

**Status:** Initial design baseline. This is not a completed security assessment or evidence of implementation.

## Assets

- User identities, sessions, app-scoped profiles, and membership/role assignments.
- Private records and uploaded objects, including their tenant and owner identifiers.
- Trusted app-context issuance, service credentials, migration credentials, and environment configuration.
- Availability and shared capacity across the target portfolio of 10–20 applications.

## Trust boundaries and assumptions

- Static UI code, SDK configuration, app IDs, storage keys, client filters, file metadata, and request bodies are attacker-controlled.
- A public anon key is not a secret. It may identify a project but must not grant privileged access.
- Database RLS, Storage policies, constraints, and trusted server functions are enforcement points.
- Trusted app context must be minted by a server-controlled mechanism, signed or otherwise verifiable, short-lived, audience-bound, and based on a server-owned app registry. Client-supplied app IDs are never sufficient.
- Shared identity does not imply shared app authorization. Local auth storage keys do not isolate browser origin capabilities.
- A same-origin XSS can read or act through browser-accessible state available to sibling apps. Prefer separate origins for apps with differing trust or sensitivity.

## Threats and required mitigations

| Threat | Example | Required design control |
|---|---|---|
| Cross-app data access | Caller substitutes another `app_id` in a query, body, URL, or SDK option | Policies derive app scope from trusted context; check membership/capability; never trust client ID filters |
| Cross-app object access | Caller guesses another app's storage prefix or changes an object path | Trusted path binding, segment validation, app status/membership checks, private buckets, immutable paths |
| Same-origin XSS | Malicious script in one UI reads local storage or uses shared origin browser capabilities | Prefer separate origins; strict CSP and dependency hygiene; minimize sensitive browser state; short-lived scoped access |
| Role escalation | User changes own role or tenant/owner columns via update, RPC, or direct REST | Revoke ordinary column writes; enforce immutable fields with constraints/triggers/trusted procedures; audit privileged changes |
| Public data leakage | Public visibility query omits app predicate | Public reads remain app-scoped and are verified by RLS; deliberate cross-app sharing requires an explicit reviewed policy |
| Storage quota bypass | Client spoofs file size or parallel uploads race quota counter | Trusted size/type checks, atomic reservations, server-side accounting, object reconciliation and rate limits |
| Migration race or stale deploy | Concurrent PR jobs mutate one staging database; old run deploys after new run | Serialize shared staging mutations, reject stale revisions, use disposable DBs for parallel tests, protect production |
| Credential/environment mix-up | Preview uses production secret or mutable SDK branch | Public-only browser credentials, isolated staging config, explicit fail-closed environment, immutable SDK versions |
| Shared-resource exhaustion | One app floods requests, uploads, auth, or egress | Server-side per-app quotas/rate limits, monitoring, alerts, abuse controls, documented exhaustion response |
| Provider failure/data loss | Free plan lacks needed backup retention or service is suspended | Verify provider capability, retain exports where feasible, define RPO/RTO, rehearse restore before storing important data |

## Security checks required before real data

1. Prove app context cannot be selected or forged by the caller and document precisely what origin binding does and does not prove.
2. Test every table operation with two users and two apps, including anonymous/public access and attempts to change tenant, owner, and role fields.
3. Test Storage list/read/create/update/delete, guessed paths, path changes, signed URL expiry, concurrent quota reservations, and reconciliation.
4. Inspect grants/default privileges, views, RPC and definer functions, safe search paths, foreign keys, and update `USING` plus `WITH CHECK`.
5. Verify the chosen provider's current plan, card requirements, rate limits, storage/egress limits, backup behavior, and recovery options.
6. Confirm alerts and a restore drill before production data is considered recoverable.

## Residual risks

- All applications sharing one backend share operational and capacity failure domains.
- An app with a shared origin may compromise another app's browser session or data accessible from that origin even when database policy is correct.
- Public static clients cannot keep a shared secret; app identification is not proof of authorization.
- Provider terms, free-tier limits, and backup features can change. The $0/no-card goal may force reduced features, capacity, or a pause.
- This model must be updated when provider, origin, authentication, SDK, data classification, or deployment choices change.
