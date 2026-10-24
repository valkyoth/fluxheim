# Commit 06: Request And Trace Correlation

Date: 2026-10-24. Review base: `d4a2569b`. Unreleased 1.9.0; this is
implementation evidence, not release acceptance. Stop for pentest and
exact-commit CI before Commit 07.

## Scope And Boundaries

The native host router establishes bounded request IDs and trace context from
the direct transport peer's configured trust, before header rewriting. Forwarded
client identity cannot grant that trust. Duplicate/malformed/oversized values
are replaced, never shortened into accepted identities. Parsing rejects
non-ASCII trace parents before byte slicing. Audit actors and audit admission
are unchanged and never derived from these diagnostic identifiers.

One completion guard follows each application request through HTTP/1.1 response
writing, HTTP/2 adaptation or connection takeover. Atomic completion prevents
duplicate outcomes; cancellation drops are bounded/nonblocking. Task-local
context isolates concurrent streams and correlates typed errors. Explicit
header removal still wins over outbound propagation. HTTP and FastCGI attempts
get distinct child spans; safe retries keep one logical request outcome.

The [tracing guide](../guides/opentelemetry-tracing.md) defines trust, sampling,
privacy, wire-completion semantics, background boundaries and loss behavior.
Only sampled trusted parents cause export; generated roots remain unsampled.
No raw targets, queries, bodies, cookies or arbitrary errors enter this schema.
Detached background tasks do not inherit task-local correlation, but existing
cache-refresh outbound header snapshots are not rewritten by this commit.
Neither trace export nor audit logging becomes durable storage.

## Verification

- Locked Linux workspace tests and strict workspace Clippy passed.
- Observability structured-event/OTLP suite: 51 tests and one compile-fail
  documentation test passed. Fixed-size queue correlation tests exercise
  actual worker JSON, trusted/untrusted inputs and length limits.
- Focused native correlation suite: seven tests passed, including concurrent
  scopes, detached tasks, duplicate/malformed/oversized context, retry IDs,
  completion cloning and real upstream header-policy removal. Privacy build:
  four focused tests passed, including absence of generated correlation.
- The live smoke starts an actual Fluxheim process, an HTTP origin, a FastCGI
  protocol fixture and a local OTLP/HTTP collector. It checks 31 distinct
  access outcomes and 48 decoded spans: concurrent static/proxy/PHP requests
  over HTTP/1.1 and multiplexed TLS HTTP/2, a stale-connection retry, stream
  reset, WebSocket tunnel, keep-alive reuse and invalid context. It checks
  parentage, unique span IDs, propagated child IDs, unsampled requests and
  absence of synthetic secret canaries in output.
- Exact-output live qualification uses one async worker with interleaved
  concurrent requests/streams and asserts zero ordinary-lane admission drops.
  Two-worker runs exposed the dispatcher's existing intentional try-lock loss
  behavior. Multi-worker task isolation has a separate native unit test;
  backpressure tests qualify bounded loss. No admission policy was weakened.
- Live smoke passed repeatedly on Linux and on native Apple Silicon macOS.
  The test collector uses persistent HTTP/1.1; its original HTTP/1.0 close
  behavior exposed intermittent export loss from stale pooled connections.
  FastCGI fixture shutdown now drains trailing protocol records instead of
  causing platform-dependent TCP resets. Exact assertions were retained.
- Windows x86_64 MSVC cross-compilation of the observability/PHP profile and
  tests passed. Native Windows execution is required in CI, not claimed here.
- Existing operational-event, file-rotation and bounded-backpressure live
  regression smokes passed. Documentation layout/baseline/link checks and
  Windows security-audit validation passed. Cargo audit and cargo-deny
  advisories reported no findings.

No dependency versions changed. Structured events now enable the already-locked
Tokio dependency for task-local context. The CI workflow runs the new live
smoke on Linux, Apple Silicon macOS and Windows. FastCGI here is a protocol
fixture, not an interpreter; backend APM ingestion, final native archives and
the real collector/container matrix remain later plan gates.
