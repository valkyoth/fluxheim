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

## Pentest Remediation: Correlation Header Ownership

Review base: `b44d1f13`. The request-ID header prefix/denylist accepted arbitrary
identity headers. Since ingress correlation replaces that header before routing,
an otherwise valid operator configuration could manufacture an authoritative-
looking identity field. This finding is fixed, not accepted as an operational
limitation.

Enabled request-ID capture now permits only `x-request-id` and
`x-correlation-id`, case-insensitively. Validation applies even when access
output is disabled, because error correlation remains active. Telemetry
construction repeats the same validation before creating the exporter or
handling requests, including programmatically constructed configurations.
With request-ID capture disabled, the unused name is not interpreted or written.

Three regression cases failed before the fix and passed afterward. Tests cover
identity/certificate/proxy-address names, arbitrary custom names, suffix tricks,
case-insensitive allowed names, disabled access output, and unchanged identity
headers for both trusted and untrusted peers. The existing live smoke now also
invokes the actual binary's configuration validator against five identity-header
configurations and requires rejection with the relevant field diagnostic.

Verification: full locked workspace tests, nine focused telemetry tests, two
configuration tests (also in privacy mode), five privacy telemetry tests,
strict workspace and observability/PHP-profile Clippy, formatting, documentation
checks and Windows MSVC test cross-compilation passed. Live configuration
rejection plus the existing 31-outcome/48-span correlation smoke passed on Linux
and native Apple Silicon macOS. No dependency versions, audit admission or
dispatcher loss policies changed. Native Windows execution remains a CI gate.

## CI And Code-Scanning Follow-Up

Review base: `fdb0a7f0`. GitHub run `40113579198` failed the Wasm-profile
Clippy gate: adding completion ownership enlarged `NativeHttp1Response`, making
the Wasm route-resolution rejection variant disproportionately large. The
rejection variant now owns a boxed response; status, body, close behavior and
the route/ACL decision order are unchanged. The same strict Clippy command
failed locally before the fix and passed afterward; no lint was suppressed.

CodeQL alert 397 identified an implicit TLS floor in the Python correlation
smoke. Its HTTP/2 client now explicitly requires TLS 1.2 or newer and asserts
the negotiated version. The fixed loopback certificate fixture remains scoped
to this smoke; production TLS configuration was not changed. Alert closure
still requires a new GitHub analysis of the fix.

Expanded Wasm testing also found a Commit 06 stack regression in the upstream
attempt wrapper. The cache-TTL test passed at pre-06 `d4a2569b`, but overflowed
the normal test stack at `fdb0a7f0`. A debugger located the overflow in the
wrapped HTTP transport future. Heap-pinning that future prevents its large
state from being embedded through nested telemetry futures. A new size-budget
test failed at 44,096 bytes before the fix and passes an 8 KiB upper bound now.
No thread-stack limit was increased in code or CI.

Verification includes all 43 native Wasm tests and the exact CI native server
suite (593 tests), both on the normal test stack, locked workspace tests,
strict workspace/Wasm Clippy and Windows MSVC test cross-compilation. Live
correlation, including header-allowlist startup rejection and TLS/HTTP2, passed
on Linux and native Apple Silicon macOS. The closed correlation-header
allowlist, provenance checks, audit admission and loss policies are unchanged.
