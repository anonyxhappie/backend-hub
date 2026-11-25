# ADR 0001: Shared multi-tenant backend for static applications

- **Status:** Accepted as an initial direction, subject to security and cost validation
- **Date:** 2026-11-25

## Context

Backend Hub is intended to support a portfolio target of 10–20 static UI applications with reusable auth, data, storage, and trusted operations. The project has a $0/no-credit-card objective. A shared backend reduces duplication but creates cross-application security and capacity risks. Static clients cannot safely keep application secrets.

## Decision

Use one shared backend as the initial design direction, with shared user identity and strictly app-scoped authorization, profiles, records, storage, and quotas. Prefer an application-specific origin for each app where app-level browser isolation matters. Use PostgreSQL RLS, Storage policies, and trusted server functions as enforcement boundaries. App context must be server-verified; a client-provided app ID or storage key is never authorization.

Keep staging and production separate. Use immutable, explicitly versioned SDK releases and server-enforced configurable quotas. Verify current provider terms and recovery features before provisioning or storing real data. The cost/card requirement is a go/no-go constraint, not an assumed free-tier entitlement.

This ADR does not authorize creation of any provider project, secret, workflow, or production resource.

## Consequences

- Shared identity is convenient, but no application inherits access to another application's data.
- A public static app cannot prove its own identity with a secret; the app-context flow and its limits must be demonstrated before schema work or real data.
- Same-origin apps remain browser-coupled and should not be described as isolated by distinct local storage keys.
- RLS, storage path policies, immutable tenant fields, and adversarial tests are foundational requirements.
- Shared capacity requires server-side quota accounting, monitoring, and a recovery plan.
- The architecture may need separate origins or separate backend projects if isolation requirements, provider limitations, or verified free capacity make the shared approach unsuitable.
- Revisit this ADR if secure app context, $0/no-card operation, 10–20 app capacity, backup/restore, or operational ownership cannot be demonstrated.
