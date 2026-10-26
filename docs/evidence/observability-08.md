# Commit 08: Bounded Collector Export Lifecycle

Date: 2026-10-26. Base: `2c3835627764cd97197708f5d2ad9681a7a04904`.
Status: implementation and local qualification complete; pentest and
exact-commit CI pending. Not release acceptance.

## Scope

Metrics and traces share a bounded HTTP delivery worker. Queue admission is
independent of collector I/O and never waits for capacity; its short bookkeeping
mutex does not discard data on ordinary contention. Queue bytes include allocated
string capacity, and elapsed deadlines
include queue residence. Response reads, attempts, retries, DNS concurrency and
shutdown are bounded. Metrics no longer perform network I/O on the async service
task. Normal runtime shutdown waits for exporters after draining requests.

Protected HTTPS bearer-token files are optional. TLS/name validation remains
mandatory. Redirects and environment proxies are disabled. Collector response
text is never copied to exporter logs. Runtime logging suppresses dependency
diagnostics within the synchronous delivery scope before formatting, even at
trace level, because HTTP libraries can log collector-controlled headers.
The live canary covers bodies, Server headers and redirect locations.
Local health has two fixed signal labels
and remains available without collector access.

See [operator policy and exact limits](../guides/otlp-export.md). One OS resolver
thread may remain stuck until the OS lookup returns. Export is not durable or
exactly-once; this does not upgrade the accepted audit persistence contract.
No HTTP/3, new public listener, UI or management mutation API is introduced.

The only lockfile changes expose already-locked `rcgen` and `rustls` to the
observability crate's tests. No package version changes.

## Verification

- Linux locked workspace suite: passed.
- Linux observability/PHP profile library suite: 293 passed.
- Observability all-features suite: 71 passed, plus one compile-fail doc test.
- Config tests with metrics/trace OTLP and propagation enabled: seven passed.
- Strict observability/PHP profile and all-features observability Clippy: passed.
- Live Linux server failure/recovery smoke: passed for both signals, including
  429/503, 400/401/403, redirects, malformed/oversized/partial replies, stalled
  response bodies, local scrape/serving isolation, capacity and canary checks.
- Same smoke in rootless Podman with the existing openSUSE runtime image: passed.
- Existing live HTTP/1.1, TLS HTTP/2, FastCGI, WebSocket, retry, cancellation,
  telemetry and exact operational metric regression smoke: passed.
- Native Windows 11 dedicated QEMU VM, non-administrator build account:
  26 OTLP tests, seven config tests and 268 observability/PHP profile tests passed.
  The live lifecycle and existing request-correlation/exact-metrics smokes passed.
- `cargo audit --deny warnings`: 449 packages, zero known vulnerabilities.
  `cargo deny check advisories`: passed.
- Formatting, documentation links/layout, modularity policy, Python compilation
  and diff whitespace checks: passed.

Windows used the existing trusted Rust 1.99.1 compiler and a separate development
source/build directory. This was native development qualification, not an official
release build: the older-than-24-hours disposable-builder gate correctly rejected
release qualification and was not relaxed. No baseline or compiler ACL was changed.

The live fixture supplies sampled trace context through an explicitly trusted
loopback peer; it does not enable hidden sample-all behavior. TLS tests use real
Rustls sockets and generated certificates, with trusted/untrusted roots, server
name mismatch, bearer credentials and redirect refusal. The localhost fixture
binds IPv6 because Windows resolves localhost to ::1 first. Accepted fixture
sockets explicitly return to blocking mode, since Windows inherits the listening
socket's nonblocking mode. A queued item can start between the active request's
timeout and the shutdown deadline; tests check the deadline and absence of an
early parallel request rather than incorrectly requiring exactly one connection.
The existing Windows correlation smoke also caught a normal-load span drop when
admission used `try_lock`. Admission now waits only for short queue bookkeeping,
never network I/O or capacity; a deterministic contention regression and the
unchanged exact-span smoke pass. Shutdown frees discarded payloads outside that
lock. Expected connection-reset diagnostics from the older Windows HTTP fixture
did not fail its assertions.

Linux, macOS and Windows CI run the OTLP-specific Rust suite and live lifecycle
smoke. Local evidence is not a substitute for the exact-SHA CI gate. Collector
product/dashboard compatibility remains a later qualification.

## Native macOS Follow-Up

On 2026-10-26, native Apple Silicon macOS 27.0.1 (26A434), Rust 1.99.1:

- A fresh private build directory used a verified source archive of
  `3281b8a3321da7af765d1f2bb0952128fd383b24`, followed by the test-only fixes below.
  No production code or dependencies changed during this follow-up.
- All-features observability tests: 71 passed, plus one compile-fail doc test.
- OTLP config tests: seven passed. Filesystem trust tests: six passed.
  Cache manifest FIFO rejection: passed.
- Observability/PHP profile library tests: 289 passed.
- Strict observability/PHP all-targets Clippy and native binary build: passed.
- Live OTLP failure/recovery smoke: passed, including local serving/scraping,
  bounded export and collector-secret canary checks.
- Existing live correlation smoke: passed, including HTTP/1.1, TLS HTTP/2,
  FastCGI, WebSocket, retry/cancellation, exact spans and operational metrics.

The new config-test compilation exposed pre-existing macOS test portability
issues. Config/cache FIFO fixtures now use the fixed `/usr/bin/mkfifo` executable
on macOS, and verify that the fixture really is a FIFO. The depth fixture uses
short components to reach Fluxheim's depth limit before macOS's pathname limit.
The cache fixture canonicalizes its temporary root to avoid the system `/var`
symlink. Production symlink rejection and the rejection assertions are unchanged.
These filesystem tests now have an explicit macOS CI step.

Linux config/cache regression suites after these fixture fixes: 436 and 67 tests
passed; strict Clippy passed. The smoke used an isolated Python 3.14.8 environment
with the unchanged pinned requirements; Apple's Python 3.9 cannot install the
pinned `h2`, which requires Python 3.10 or newer. No global toolchain, Python
installation or other project's build directory was modified.

## Pentest Follow-Up: Collector Transport

The review of `2c383562..64306e33` identified the inherited warning-only policy
for remote plaintext OTLP as unsuitable for confidential telemetry. This is now
a fail-closed policy for both metrics and traces: HTTPS is required except for
numeric loopback HTTP (`127.0.0.0/8` and `::1`). DNS names, including `localhost`,
private networks, IPv4-mapped IPv6 and ambiguous numeric forms do not receive
the plaintext exception. Private collectors remain supported over verified HTTPS.

Config validation and direct exporter construction call the same shared rule.
Runtime rejection occurs before credential-file access, DNS or worker creation.
Bearer credentials still require HTTPS even on loopback. FIPS restrictions,
certificate verification, redirect refusal and existing queue/deadline policies
are unchanged. No dependency or lockfile changed. This intentionally requires
operators of remote HTTP collectors to migrate; the migration is documented in
the [export guide](../guides/otlp-export.md).

Validation of the remediation on 2026-10-26:

- Full locked Linux workspace tests: passed.
- Observability all-features tests on Linux and native Apple Silicon macOS:
  72 passed plus one compile-fail doc test each. OTLP config tests: eight passed.
- Observability/PHP profile tests: Linux 293 and macOS 289 passed.
- Strict Clippy: passed for the Linux all-features observability crate and
  Linux/macOS observability/PHP profiles. Standalone `otlp-http` compilation passed.
- Live Linux and macOS exporter lifecycle and correlation smokes: passed.
  The lifecycle smoke now also executes binary config validation for both signals,
  asserting rejection of remote/private/DNS HTTP and acceptance of numeric
  loopback HTTP and private/DNS HTTPS, without contacting those remote endpoints.
- The expanded lifecycle smoke also passed in the rootless Linux container.
- `cargo audit --deny warnings` and `cargo deny check advisories`: passed;
  449 locked packages, zero known vulnerabilities.
- Formatting, documentation links/layout, Python compilation, modularity and
  diff checks: passed.

Native Windows was not rerun for this shared policy-only remediation. Existing
Windows CI executes the new unit and binary smoke assertions. Pentest retest and
exact-commit GitHub acceptance remain pending; prior Windows evidence is not
presented as a new Windows run.
