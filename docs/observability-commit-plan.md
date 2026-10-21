# 1.9.0 Observability Commit Plan

Status: active release plan, agreed 2026-10-21. Implementation checkpoints have
not started. `main` remains 1.9.0 (unreleased); v1.8.2 is the published baseline.
This plan supersedes older assignments of HTTP/3 to 1.9 and observability to
1.10 or 1.13. Later management API/UI milestones remain proposals, not a
renumbered release commitment.

The `1.8.x` maintenance branch starts from v1.8.2 and prepares 1.8.3 separately.
Dependency/container/runtime fixes can ship there after their own qualification
without waiting for this implementation train. Keep shared fixes on both lines;
do not merge 1.9 planning or unfinished features into the maintenance release.

## Operator Outcome

An operator should be able to diagnose a failed upstream connection, PHP
request, cache operation, certificate renewal or reload without enabling
unsafe debug dumps. Logs, metrics and traces should correlate, describe the
same outcome, remain bounded under load, and make telemetry failures visible
without making a healthy webserver unavailable.

Deliver one coherent 1.9.0 release after the checkpoints below. Use 1.9.x for
bug/security fixes and compatible follow-up work, not partially usable pieces
of the initial implementation. Existing configuration remains valid; new
expensive or sensitive telemetry is opt-in. Do not silently change privacy
mode, expose administrative listeners or add public diagnostic headers.

## Existing Baseline

Start from actual implementation, not the aspirational architecture documents:

- `src/runtime_logging.rs` configures the current `log`/`env_logger` pipeline,
  JSON/text output and protected local files.
- `fluxheim-observability` already supplies access events, request IDs, trace
  context, label helpers, Prometheus secret handling and OTLP encoders/export.
- Runtime metrics and administrative status already expose operational data.
- The [logging](logging-architecture.md), [metrics](metrics-architecture.md)
  and [tracing](opentelemetry-tracing.md) documents contain both delivered
  behavior and future ideas. Commit 01 must distinguish them explicitly.
- `scripts/smoke_observability_local.sh` and native platform smoke suites
  provide a starting point, not proof of every new contract below.

Keep the Rust/dependency updates, Windows builder improvements and
[container runtime refresh workflow](container-runtime-refresh.md). None of
those changes requires production HTTP/3.

## Boundaries

- Reuse existing ownership: configuration in `fluxheim-config`, shared
  telemetry types/export in `fluxheim-observability`, runtime integration in
  existing server modules. Avoid exporting backend-library types as public
  configuration or making a telemetry crate depend on the entire server.
- No HTTP/3, new crypto provider, full management API, UI, arbitrary remote
  commands, new protocol or mandatory external collector in this release.
- The [HTTP/3 plan](http3-quic-commit-plan.md) and probes remain deferred
  research. Reconsider Brynja/Vef after capability/security qualification;
  neither is a current dependency. Normal CI does not run the source probes.
- Remote log shipping and durable disk spooling remain future work unless a
  separately reviewed scope revision adds their lifecycle and security tests.
  Existing OTLP export is in scope; promising every sink in an older design
  document is not.
- Preserve HTTP/1.1, HTTP/2, TLS, PHP, ACME, proxy/cache/load-balancer and Wasm
  behavior. Windows PHP remains external TCP FastCGI, never managed php-fpm.
- Public errors stay generic. Private structured diagnostics use bounded,
  reviewed reason codes. No credentials, tokens, cookies, bodies, private keys,
  query values or unfiltered upstream errors in logs, labels or trace baggage.

## Checkpoint Procedure

For each numbered commit: record the starting commit and agreed scope,
implement with focused regressions, run applicable broader/platform gates,
and record commands, results and limitations. Commit the work, then stop for
the user's incremental pentest. Fix findings with regression tests, wait for
retest and GitHub green, and obtain authorization before the next checkpoint.
GitHub green is necessary but does not substitute for live-platform evidence.
No failed test may be weakened just to match a new failure path.

Each `Commit NN` is a review boundary; remediation may require several Git
commits. Keep a ledger of accepted commit IDs and evidence as work proceeds.
No checkpoint is accepted merely because its plan is written.

## Commit 01 - Inventory And Stable Telemetry Contracts

Deliver an implementation inventory and versioned event/metric field tables.
Define units, counter versus gauge semantics, severity, reason codes, lifecycle
and correlation rules for successful, rejected, cancelled and failed requests.
Document reload compatibility and what needs a restart. Classify existing
dashboards/export fields as compatibility contracts; deprecate rather than
silently rename them. Capture current overhead and memory baselines.

Exit: fixtures for current JSON, Prometheus and OTLP output, tests of parsing
and privacy defaults, updated architecture docs with implemented/planned
sections, and a concrete gap list for the following checkpoints.

## Commit 02 - Actionable And Safe Failure Diagnostics

Add consistent internal reason codes for upstream DNS/connect/TLS/timeout,
PHP/FastCGI, cache storage/encryption, ACME and reload/rollback failures.
Retain the original causal category without leaking raw secrets or topology
to clients. Audit authenticated admin operations with action/outcome and safe
identity classification. Bound field sizes and repeated-event emission.

Exit: provoke each failure and assert its event, public response, redaction and
request outcome. Include CR/LF/control characters, oversized fields and
secret canaries; prove disabled access logging cannot accidentally suppress
required security/audit events under the agreed policy.

## Commit 03 - Bounded Logging And Sink Lifecycle

Implement a bounded dispatcher where the inventory identifies synchronous
request-path logging. Bound both event count and total bytes. Define queue
overflow, counters, shutdown flush deadlines and file reopen behavior across
reload/rotation. Preserve existing JSON/text and stdout/stderr/file options.
Select any logging backend migration only after compatibility tests, avoiding
duplicate events from `log`/`tracing` bridges. Do not claim lossless logging.

Exit: blocked/closed pipe, slow disk, full disk, permission failure, rotation,
queue saturation and cancellation tests; no recursive logging storm or
unbounded tasks. Demonstrate bounded latency/memory against Commit 01's
baseline with explicit budgets recorded before acceptance. Cover Unix
ownership/symlinks and Windows ACL/reparse protections for file sinks.

## Commit 04 - Request And Trace Correlation

Unify request IDs across access/error events, upstream requests and sampled
traces. Validate untrusted inbound IDs/context, define proxy trust and
sampling behavior, and prevent request cross-contamination under concurrency.
Do not add sensitive baggage or raw URL/query trace attributes by default.

Exit: concurrent HTTP/1.1 and HTTP/2 requests through static, proxy and PHP
paths retain the correct correlation; malformed/oversized context is rejected
or replaced according to the contract. Cancellation, retry and streaming
requests produce consistent outcomes and no duplicate completion events.

## Commit 05 - Useful Metrics With Bounded Cardinality

Close inventory gaps for connection/request admission, upstream health and
failures, cache hits/misses/storage, PHP, ACME, reload and telemetry health.
Use finite reason/status labels and configured identity limits. Never label
with request IDs, client addresses, URLs, arbitrary Host values or error text.
Bound configured-label churn across reloads and validate histogram buckets.

Exit: predictable counters/gauges/histograms under success, timeout, rejection,
disconnect and shutdown; random paths/hosts cannot grow series without bound.
Metrics privacy/authentication and feature-disabled builds remain correct.

## Commit 06 - Export Failure And Recovery

Harden existing OTLP metrics/tracing export with bounded queues, payloads,
in-flight work, timeouts, retry/backoff and shutdown drain. Validate collector
TLS and authentication without exposing secrets. Surface dropped data and
collector failure locally, without request-path network I/O or retry storms.

Exit: unavailable/slow collector, TLS mismatch, oversized/bad responses,
authentication rejection and recovery tests. Check byte and task bounds,
privacy-mode feature rejection and empty/disabled export behavior.

## Commit 07 - Read-Only Operational Visibility

Expose a bounded summary through existing authenticated admin/status surfaces:
logging/export health, last reload result, listener/upstream/cache/ACME/PHP
status where already owned by the runtime. Distinguish liveness, readiness
and degraded telemetry; collector failure alone must not falsely kill a
healthy service. No new mutation/control-plane framework.

Exit: auth-before-side-effects and secret-redaction tests, bounded response
size, correct status during reload/rollback/drain, and no unauthenticated
disclosure of backend addresses or filesystem paths.

## Commit 08 - Live Containers And Collectors

Run a packaged Fluxheim container with real HTTP/HTTPS clients, a controllable
origin, Prometheus and a real OTLP collector/trace backend. Send uniquely
identified requests; assert actual stored/scraped measurements and trace/log
correlation rather than only HTTP 200 from a health endpoint. Exercise cache,
PHP and upstream TLS failures, collector stop/restart and graceful shutdown.
Pin test dependencies and provide deterministic cleanup/artifact collection.

Exit: repeatable container smoke with a required-collectors mode. Missing
prerequisites or skipped collector checks are explicitly incomplete, never a
successful release gate. Assert expected values and secret-canary absence.
Retain failing logs locally without publishing credentials or bodies.

## Commit 09 - Native Platform And Archive Proof

Test Linux x86_64/aarch64, Apple Silicon macOS and Windows x86_64 artifacts on
their actual operating systems. Exercise extracted release binaries, JSON
logs, file rotation/reopen, Prometheus scrape, OTLP delivery/recovery and
shutdown while real HTTP/HTTPS traffic flows. Use external TCP FastCGI on
Windows. Include off-host requests in disposable-host qualification where
applicable and record firewall/network prerequisites.

Exit: archive/profile matrix records feature-present and feature-absent
behavior, OS version, commit, toolchain, commands and evidence. A Linux
cross-build is not native execution; macOS is not assumed equivalent to Linux.
No need for public production services or real customer data. Container
collector tests complement, rather than replace, native process tests.

## Commit 10 - Documentation And Release Gate

Publish configuration/migration examples, field reference, troubleshooting
recipes and baseline dashboards. Explain diagnostic privacy, bounded-loss
semantics, optional collectors, authentication and platform differences.
Synchronize README, release notes, RPM, archive and container metadata.

Exit: full workspace/profile/lint/security gates, container and native smoke
evidence on the final candidate, fuzz/negative tests for changed parsers,
load/overhead comparison, independent pentest/retest and green GitHub.
Only then authorize signed 1.9.0 tagging/publication. Report any unexecuted
platform gate as a release blocker, not a passing check.

## Acceptance Ledger

| Checkpoint | State | Accepted commit / evidence |
| --- | --- | --- |
| 01 - Contracts | Not started | Pending |
| 02 - Diagnostics | Not started | Pending |
| 03 - Logging lifecycle | Not started | Pending |
| 04 - Correlation | Not started | Pending |
| 05 - Metrics | Not started | Pending |
| 06 - Export | Not started | Pending |
| 07 - Status | Not started | Pending |
| 08 - Containers | Not started | Pending |
| 09 - Native artifacts | Not started | Pending |
| 10 - Release | Not started | Pending |
