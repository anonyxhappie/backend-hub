# Agent instructions

## Project purpose

Backend Hub is a shared backend foundation for a target portfolio of 10–20 static UI applications. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and security invariants. The $0/no-credit-card objective is a constraint to verify with current provider terms, not a promise about free tiers.

## Rules for all contributors and coding agents

- Read this file, `ARCHITECTURE.md`, and the relevant sections of `AGENT_PLAYBOOK.md` before changing schemas, authorization, storage, SDK contracts, or deployment behavior.
- Treat app context as a trusted server-issued authorization fact. Never use a client-supplied `app_id`, `storageKey`, path, origin string, or SDK filter as proof of app authorization.
- Keep tenant and owner identifiers, membership roles, and other security fields immutable to ordinary clients. Enforce rules in PostgreSQL RLS/constraints, Storage policies, and trusted functions, not only in browser code.
- Keep service-role keys and other privileged credentials out of browser bundles, repository history, logs, previews, and test fixtures.
- Assume apps sharing an origin share browser security risk. Do not describe separate local storage keys as security isolation.
- Preserve explicit staging/production separation. Never deploy, seed, or run destructive migration steps against production without a reviewed, user-approved change request and the repository's documented release controls.
- Do not add deployment workflows, secrets, cloud resources, Supabase projects, or paid services unless the task explicitly requests them. Documentation must label unverified provider assumptions.
- Treat quotas as server-enforced policy and provider limits as variable. A client-side check or free-tier marketing page is not enforcement or a lasting guarantee.
- Pin production SDK consumers to immutable releases; do not use a mutable branch URL.
- Keep this project agent-agnostic. Follow this file and the playbook regardless of the editor or coding agent.

## Change expectations

For security-sensitive changes, explain the trust boundary, affected policies, and failure behavior in the change description. Update architecture/ADR docs when a design invariant changes. Add adversarial authorization tests when implementation exists and test behavior when requested. Do not claim security, free-tier eligibility, backup coverage, or deployment readiness without evidence.

Keep changes focused, readable, and reversible. Never commit secrets or real user data.
