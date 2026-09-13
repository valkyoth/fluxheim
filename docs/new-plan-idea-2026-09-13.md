# New Plan Idea - 2026-09-13

Status: discussion draft. This document records a possible product direction
and does not replace the active versioning plan, authorize implementation, or
promise release dates or version numbers.

## Motivation

Fluxheim's existing versioning plan contains a mixture of concrete production
work and older exploratory ideas. Now that the project has native Linux,
Apple Silicon macOS, and Windows x86_64 release paths, a smaller sequence of
coherent product milestones may provide more value than continuing every
previously suggested feature line.

The proposed progression is:

1. `1.9.0`: HTTP/3 and QUIC data-plane support.
2. `1.10.0`: advanced logging, metrics, tracing, and operational visibility.
3. `1.11.0`: a complete, versioned management API.
4. After `1.11.0`: begin a separate `fluxheim-ui` project that manages one or
   more Fluxheim servers through the published management API.

Patch releases within each line remain available for complete user-facing
improvements, bug fixes, and security fixes. Internal refactoring or planning
work does not by itself require a public release.

The current versioning plan assigns `1.10` to privacy and security profiles and
`1.13` to advanced metrics and logging. Adopting this proposal would require a
reviewed renumbering pass. Existing useful requirements should be moved, not
silently discarded.

## 1.9.0 - HTTP/3 And QUIC

Complete the separate numbered HTTP/3 implementation train before changing the
control plane. The first public release should provide a coherent opt-in
downstream HTTP/3 service rather than partial protocol releases.

The detailed scope, security boundaries, native platform proofs, pentest stops,
and future cryptographic replaceability requirements are maintained in the
[HTTP/3 And QUIC Commit Plan](http3-quic-commit-plan.md).

## 1.10.0 - Observability Maturity

Goal: establish stable operational contracts that administrators, monitoring
systems, automation, and the future UI can consume without scraping unstable
logs or inventing another telemetry model.

Candidate stable scope:

- Stable metrics names, types, labels, units, and compatibility policy.
- Explicit cardinality budgets enforced by tests.
- Per-vhost, route, upstream, cache, TLS, ACME, HTTP-version, PHP, Wasm, and
  load-balancer visibility where the corresponding feature is enabled.
- Structured, versioned operational and security event schemas.
- Audit events for every administrative mutation and recovery action.
- Request-ID and trace-context correlation across access logs, upstream work,
  cache activity, errors, and administrative actions.
- Log redaction, filtering, sampling, rotation, backpressure, and bounded sink
  failure behavior.
- Prometheus and OpenTelemetry metric parity for admitted measurements.
- OpenTelemetry trace export with bounded attributes and deterministic failure
  semantics.
- Health and readiness explanations instead of only binary state.
- Bounded recent operational summaries through authenticated admin endpoints.
- Explicit privacy-mode behavior for every log, metric, trace, event, and
  administrative response field.
- Native Linux, macOS, and Windows evidence plus rootless-container evidence.

Important limits:

- User-controlled hostnames, paths, addresses, request IDs, connection IDs, and
  error strings must not become unbounded metric labels.
- Detailed packet, certificate, backend, cache-key, and filesystem information
  remains private and opt-in where it can expose deployment topology or user
  data.
- Exporter or log-sink failure must not block the request path indefinitely or
  create unbounded queues.
- Observability endpoints are not a configuration mutation channel.

This work should precede the full management API so `1.11.0` exposes one mature
operational model instead of creating UI-specific counters and events.

## 1.11.0 - Complete Management API

Goal: make Fluxheim fully manageable through a stable authenticated API while
preserving declarative configuration, validation, snapshots, auditability, and
fail-closed rollback.

The management API should not become unrestricted mutation of internal runtime
objects. It should be a transactional interface around Fluxheim's declarative
configuration and existing runtime operations.

### Configuration Transaction Model

A normal configuration change should follow this sequence:

1. Read the active configuration and immutable revision identity.
2. Create or update a bounded draft based on that revision.
3. Validate the complete draft without applying it.
4. Return structured errors, warnings, compatibility information, and a change
   plan.
5. Compare the draft with the active configuration using a structured diff.
6. Commit the accepted draft into the authenticated snapshot store.
7. Atomically apply changes classified as snapshot-safe.
8. Report changes that require process replacement without partially applying
   them.
9. Confirm health within a bounded validation window or automatically roll back
   to the previous known-good revision.
10. Preserve a durable audit record linking actor, request, revision, snapshot,
    validation result, application result, and rollback result.

### Managed Domains

Candidate stable API domains include:

- Server and listener configuration.
- Vhosts and routes.
- Static roots and redirect policy.
- Reverse proxies, upstream TLS, retries, and timeouts.
- Cache configuration, inspection, warming, and purge operations.
- Header, CORS, access, authentication, GeoIP, and privacy policies.
- PHP/FastCGI configuration with platform capability validation.
- TLS policy, certificate references, and client authentication.
- ACME account, issuer, target, issuance, renewal, and revocation operations.
- Load-balancer pools, discovery, health, runtime state, weights, and member
  lifecycle.
- Wasm module references and policy bindings without arbitrary module upload by
  default.
- Snapshot creation, listing, verification, comparison, application, rollback,
  pruning, and recovery state.
- Health, readiness, metrics summaries, audit events, and runtime status.
- Graceful drain and process-replacement planning where supported.

### API Contract

The management surface should include:

- Explicit versioned routes such as `/api/v1/...`.
- A committed OpenAPI specification and generated contract validation.
- Stable resource identities and schemas rather than unstructured text fields.
- Optimistic concurrency through revision IDs or ETags.
- Idempotency keys for retried mutations.
- Dry-run, validation, plan, and diff endpoints.
- Bounded pagination and response-size limits.
- Consistent structured errors with stable low-cardinality error codes.
- Capability discovery so clients can identify compiled features and platform
  limitations before submitting a change.
- A compatibility policy for additive fields, removals, deprecations, and API
  version transitions.

### Authentication And Authorization

Remote management requires a stronger control plane than the current local
bearer-token listener:

- Native TLS and mutually authenticated TLS for the admin listener.
- Short-lived credentials or tokens derived from a reviewed identity boundary.
- Scoped roles such as viewer, operator, configuration administrator, security
  administrator, and certificate administrator.
- Per-operation authorization checked before parsing or performing sensitive
  side effects where practical.
- Brute-force throttling, replay protections where relevant, session expiry,
  credential rotation, and revocation.
- Complete mutation audit records without logging tokens, secret values, or
  private keys.
- Local-only and air-gapped operation retained as first-class deployments.

### Secret And Filesystem Boundaries

The API should manage references and lifecycle operations, not become a general
secret or filesystem service:

- Secret responses never return private-key, token, password, EAB, HMAC, or
  encryption-key contents.
- Configuration uses typed secret references with existence and permission
  validation.
- Arbitrary filesystem reads, writes, path browsing, executable hooks, command
  execution, and process spawning are excluded.
- Certificate or Wasm upload, if ever admitted, requires separate bounded
  content APIs, strict type/size validation, atomic publication, audit records,
  and explicit operator policy.
- Backup and export operations return bounded defined formats and cannot accept
  arbitrary destination paths.

### Runtime And Process Boundaries

The API can plan process-level changes but should not pretend every change is a
safe in-process reload:

- Snapshot-safe changes use atomic runtime replacement and rollback.
- Listener, TLS backend, admin transport, metrics service, and startup-owned
  background-service changes may require supervisor-controlled process
  replacement.
- The API returns a machine-readable classification before commitment.
- Service installation, operating-system updates, package replacement, and
  host reboot remain the responsibility of an external supervisor or deployment
  system.
- Any future restart endpoint must use a narrowly defined supervisor protocol;
  it must not execute caller-provided commands.

## Separate Fluxheim UI Project

After the `1.11` management contract is stable, create a separate GitHub
repository named `fluxheim-ui`. Keeping it separate preserves Fluxheim's CLI
and server focus, allows an independent release lifecycle, and avoids making a
large user-interface dependency graph part of the webserver binary.

The preferred initial shape is a self-hosted web application with a small
backend/controller. Browser JavaScript should not connect directly to every
Fluxheim admin listener or hold every server credential.

The controller can:

- Register and identify one or more Fluxheim instances.
- Store per-instance mTLS identities or short-lived credentials through a
  reviewed secret-storage boundary.
- Aggregate health, readiness, metrics summaries, alerts, and audit events.
- Edit drafts and show validation errors and structured diffs.
- Coordinate staged configuration deployment, health confirmation, rollback,
  drain, and process-replacement plans.
- Provide organization-level users, roles, and authorization independently of
  each managed instance.
- Support isolated, self-hosted, and air-gapped installations.
- Display explicit capability and version differences across a mixed fleet.

The UI must consume only the published management API and OpenAPI contract. It
must not depend on Fluxheim's internal Rust modules, edit server files over SSH,
scrape logs as its primary state source, or require Fluxheim to be managed by a
UI. CLI, configuration-file, automation, and direct API workflows remain fully
supported.

A desktop wrapper can be evaluated later if it provides deployment value, but
it should use the same controller and API contracts rather than creating a
second management protocol.

## Proposed Delivery Method

If selected, both `1.10.0` and `1.11.0` should receive separate numbered commit
plans like the HTTP/3 train:

1. Freeze finite scope and source contracts.
2. Implement one reviewable boundary at a time with permanent tests.
3. Commit each numbered checkpoint normally.
4. Pentest the complete diff from the preceding accepted checkpoint.
5. Commit remediation and retest until green.
6. Wait for all required GitHub CI and CodeQL checks before starting the next
   numbered checkpoint.
7. Run a full-project pentest, native platform tests, live container tests, and
   release gate only at the final candidate.

The future UI should have its own threat model and commit plan. A vulnerability
in the UI/controller must not grant more authority than the authenticated role
and target Fluxheim instance explicitly allow.

## Decision Questions

Before replacing the active roadmap, decide:

1. Which existing `1.10` through `1.15` ideas remain valuable enough to move,
   defer, or remove?
2. Is fleet management a required `fluxheim-ui` capability from its first
   release, or should the first UI support one server only?
3. Should configuration resources be exposed as typed domain objects, a
   complete TOML document, or both with one canonical representation?
4. Which identity system should the management API support initially beyond
   mTLS and local bearer tokens?
5. Which administrative operations must remain local-only even when remote
   management is enabled?
6. What audit retention and export guarantees are required?
7. Which process-replacement supervisor contracts are supported on Linux,
   macOS, and Windows?
8. Is `1.11.0` the point where the management API becomes a stable compatibility
   promise, or should it first ship as an explicitly versioned preview?
