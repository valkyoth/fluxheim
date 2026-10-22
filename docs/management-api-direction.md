# Management API And Fluxheim UI Direction

Status: recommendation for discussion, 2026-10-22. Not an implementation
authorization or a promise of complete F5 BIG-IP product parity.

## Recommended Sequence

1. Deliver [1.9.0 observability](observability-commit-plan.md): safe diagnostics,
   bounded logging/metrics/export, correlation and a stable read-only operational
   API contract. This is already a substantial cross-platform release.
2. Use a separate minor release, provisionally **1.10.0** if approved, for
   complete Fluxheim management. Give it its own numbered implementation plan,
   incremental pentests, CI stops and live end-to-end gates. Existing historical
   1.10/1.11 roadmap ideas are not automatically discarded or renumbered.
3. Build **fluxheim-ui** in a separate repository against that published API.
   UI mockups and an API client prototype may start earlier, but do not promise
   complete management until the API coverage and security gates are accepted.

The API should live with Fluxheim's existing administrative runtime and be
optional at deployment, not become a second server fork or a special binary
with different configuration semantics. The UI/controller has an independent
release lifecycle and must not be required for normal file/CLI operation.

## What Exists And What Is Missing

The current router in `src/admin/request_router.rs` has health/status, cache
status/purge/reset, load-balancer status/member controls, snapshot and
self-healing operations. Existing authentication, throttling, local ops and
snapshot/recovery code provide a useful base. This is **not** complete CRUD
for all configuration and not yet a versioned fleet-management API.

Do not advertise the mere presence of mutation endpoints as full management.
For example, changing a live pool member is different from durably updating
the declarative configuration and retaining that change after restart.

## Define "Everything Through The API"

Every supported Fluxheim configuration domain and server-owned operation must
have a documented API workflow, or an explicit capability result explaining
why that operation is unavailable in this build/platform/deployment. The UI
must not need SSH, shell commands, hidden filesystem edits or private Rust APIs.

The future API plan starts with a coverage matrix derived from every config
schema, CLI command and runtime operation, not a handpicked screen list:

| Domain | Required management outcome |
| --- | --- |
| Listeners, vhosts, routes, static/proxy/redirect | Read/edit/validate/diff/commit configuration; classify reload versus restart |
| Headers, limits, auth, GeoIP and privacy | Same complete config workflow; no UI-only defaults or validation rules |
| Cache | Configuration plus bounded inspection/purge/warm jobs and results |
| Load balancing and discovery | Pools/members/health/weights/drain; clearly distinguish temporary overrides from persistent config |
| PHP and Wasm | Validated references and bindings; capability-aware Unix managed PHP versus Windows external TCP FastCGI |
| TLS and ACME | Certificate/issuer/account references and bounded lifecycle jobs with progress, failure and audit |
| Snapshots and recovery | Create/list/verify/diff/apply/confirm/rollback/prune with durable revisions and fail-closed recovery |
| Runtime and telemetry | Health, capabilities, listener state, metrics summaries, audit and job status |
| Restart-required settings | Machine-readable change plan and explicit supervisor handoff, never a false successful live apply |

"Everything" does not mean host root access. OS patching, package installation,
firewall changes, host reboot, database administration and site-content editing
belong to external deployment/application tools. A future supervisor adapter
could implement a narrow restart/upgrade protocol, separately authorized and
tested, not arbitrary commands supplied by a caller.

The distinction must be visible in the UI: supported/live, supported/restart
required, feature absent, platform unsupported and externally managed are
different states. Do not hide an unimplemented workflow behind "success".

## Core Contracts Before A Full UI

- **Declarative transactions:** read an active revision, create a bounded draft,
  validate the whole configuration, preview a structured diff/change plan,
  commit atomically, apply, health-confirm or roll back. Define persistence,
  crash recovery and interaction with file/conf.d edits; avoid two competing
  sources of truth or silent overwrite of operator changes.
- **Concurrency:** revision preconditions prevent lost updates. HTTP `If-Match`
  is a standard conditional-request mechanism suitable for this boundary.
  Retried mutations also need bounded idempotency records and conflict rules.
  See [RFC 9110 section 13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match).
- **Stable schemas:** publish OpenAPI, capability discovery, structured errors,
  pagination/response limits and compatibility rules. Select a schema version
  supported by the chosen tooling, not simply the newest label. OpenAPI
  describes HTTP interfaces for clients without access to implementation code;
  [OpenAPI](https://spec.openapis.org/oas/latest.html) and
  [RFC 9457 problem details](https://www.rfc-editor.org/rfc/rfc9457.html) are
  candidate contracts, not evidence of an API already implemented here.
- **Identity and permissions:** remote TLS authentication, scoped viewer,
  operator/config/security roles, token/certificate rotation and revocation,
  per-operation and resource checks, and auditable actors. Reusing one shared
  bearer token is not a complete user or tenant permission model.
- **Bounded jobs:** ACME, warm/verify and other long operations need stable job
  IDs, deadlines, cancellation, restart semantics and bounded retention. An
  accepted job is not a successful completed change.
- **Secrets:** manage references and write-only provisioning where explicitly
  supported, never echo keys/passwords/tokens in reads/diffs/audit. Redacted
  reads must round-trip safely without replacing secrets with redaction text.
  Any certificate/module content API requires separate size/type/integrity,
  publication, trust and audit design; no arbitrary path upload endpoint.
- **Recovery:** concurrent mutations, timeouts, rollback failure, daemon crash,
  disk full, stale confirmation and lost client responses must not bless an
  unhealthy candidate or partially apply a restart-only transaction.

## UI Deployment Model

Prefer a self-hosted web UI with a controller/backend that holds narrowly
scoped per-instance credentials. Browsers authenticate to the controller;
they should not store a fleet's admin credentials or connect directly to every
administrative listener. Review CSRF, sessions, SSRF during server enrollment,
credential storage, tenant boundaries and audit independently of Fluxheim.

Start with a complete single-server workflow, then fleet inventory and staged
deployment. Multi-server changes are not one atomic transaction: report
partial success, stop/rollback policy and per-server revisions explicitly.
Fluxheim enforces its own authorization regardless of what the UI permits.

## Acceptance For The Management Release

Use an API-only test client from a separate host to enroll a server, inspect
capabilities, create a vhost/upstream, validate/apply, serve real HTTPS traffic,
change configuration concurrently, trigger an invalid rollout, recover and
verify persistence after restart. Cover secret references and TLS/ACME staging
without extracting secrets. Reject forbidden-role and stale-revision requests.

Run the workflow on Linux, Apple Silicon and Windows, including platform
limitations and restart-required changes. Verify the coverage matrix against
the config/CLI inventory so new settings cannot silently become UI-inaccessible.
Require independent pentest/retest and green CI at each numbered checkpoint.

The management release is done when the defined Fluxheim-owned workflows are
complete, not when a dashboard can display counters. Appliance features such
as clustering, WAF, VPN or network control are separate product decisions.
