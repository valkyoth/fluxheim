# Commit 07: Bounded Operational Metrics

Date: 2026-10-25. Review base: `b563894556fa4ef475f7f7bd27cf957de86e7b80`.
Unreleased 1.9.0 implementation evidence, not release acceptance. Stop for
pentest, exact-commit GitHub/CodeQL and user approval before Commit 07A.

## Scope And Contracts

The [metrics guide](../guides/metrics.md) defines the metric names, finite label
domains, units, histogram bounds, accounting and unavailable panels. An optional
typed measurement hook connects existing request, transport, listener, failure,
security and audit owners to the process registry. Measurements precede log
filtering/admission and do not depend on trace sampling or successful log writes.
No HTTP headers, URLs, arbitrary error strings or client identities enter the
new label domains. Privacy builds still reject metrics at compile time.

Logical request completion remains owned by Commit 06's one-shot completion
guard. Attempts count separately, including retries and cancellation. Connection
task ownership balances the active gauge on completion or cancellation, including
cancellation before first polling. TLS results count connections, not HTTP/2
streams. Body-byte accounting excludes partial failed writes and tunnel payload.
An HTTP 5xx response successfully written downstream is a completed request with
a 5xx status class; it is not automatically a failed downstream transport.

Existing variable-label vectors now admit identities before allocating children:
19,000 exported samples across families, at most 2,048 per family, with a separate
1,000-sample reserve for fixed domains. Histogram buckets, sum and count consume
budget. Counter/histogram overflow preserves aggregates in a reserved tuple;
gauges discard excess identities instead of inventing an aggregate. Labels are
bounded to six values of at most 128 bytes each. Reload churn cannot continually
allocate new lifetime counter identities. Successful admin reload refreshes
configuration gauges and retires idle-pool observations without resetting totals.

Length-prefixed admission keys alone were insufficient: the underlying
Prometheus vector concatenates label values when hashing children. The regression
for `(a, bc)` versus `(ab, c)` initially failed. Each admitted tuple now owns an
independent child, and collection retains the original exported labels. The
all-`overflow` tuple is reserved to prevent duplicate exported samples. Collection
copies bounded child handles under a short lock, then formats outside that lock.

Dispatcher-health collection takes fresh atomic snapshots, without exporter-side
delta accumulation. Unavailable workers/dispatchers are not represented as healthy
zero failures. A real injected sink failure remains observable without delivery
of the corresponding log record. Audit metrics do not change admission policy or
make audit persistence durable. Prometheus and OTLP use the same registry;
OTLP unit metadata now reflects bytes, seconds or dimensionless values.

## Verification

Commands use the locked workspace and pinned Rust 1.99.1. Feature combinations
matter; the observability/PHP binary is built separately from default workspace
test artifacts before live testing.

```bash
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --no-default-features --features profile-observability,php-fpm --lib metrics
cargo clippy --locked --no-default-features --features profile-observability,php-fpm --all-targets -- -D warnings
cargo clippy --locked --no-default-features --features profile-wasm --all-targets -- -D warnings
cargo test --locked -p fluxheim-server --lib --features wasm,php-fpm,tls-rustls,load-balancer
cargo test --locked -p fluxheim-observability --all-features
cargo test --locked --no-default-features --features profile-privacy --lib
cargo test --locked -p fluxheim-server --features otel-otlp,privacy-mode native_request_telemetry
cargo fmt --all --check
cargo audit --deny warnings
cargo deny check advisories
```

- Linux workspace tests and strict workspace/observability/Wasm-profile Clippy
  passed. The native server feature suite passed 593 tests. The final focused
  metrics suite passed 49 tests, including sink failure, authenticated metrics
  access, reload observation retirement and unchanged lifetime totals.
- Churn tests cover 100,000 identities, concurrent first use, oversized/mismatched
  labels, shared histogram/counter budgets, family starvation, tuple collisions,
  reserved overflow and gauge reset. A separate Linux subprocess saturates the
  19,000-sample variable budget, then performs approximately one million updates.
  Recorded RSS was 10,379,264 bytes before, 31,801,344 after warm-up and unchanged
  after churn. Assertions bound initial growth to 64 MiB and subsequent growth
  to 8 MiB. These are collector-allocation checks, not a whole-server RSS ceiling.
- Privacy-profile root tests (194) and privacy telemetry tests (6) passed.
  Unsupported privacy-plus-metrics builds still fail; no policy was relaxed.
- Windows MSVC cross-compilation of the observability/PHP test profile passed.
  Native Windows and final macOS results are recorded below; cross-compilation
  alone is not runtime evidence.
- Dependency audit and deny advisories passed with 449 locked packages and no
  known advisories. No manifests or lockfiles changed in this checkpoint.

A local diagnostic baseline used three alternating telemetry-off/on pairs,
500 requests per run and eight clients with a debug binary. Off runs measured
2,450-2,684 requests/s and on runs 2,503-2,624 requests/s; p99 was 4.63-4.81 ms
off and 4.41-4.80 ms on. Peak RSS ranged from 35.4 to 36.5 MB and shutdown took
approximately 1.015 seconds. Each enabled run delivered four OTLP metric batches;
traces were unsampled. This is a noisy local sanity check, not a controlled
before/after release benchmark or independent proof of an overhead percentage.

The expanded `scripts/smoke_request_correlation.py --binary PATH` starts real
Fluxheim, a controlled HTTP origin, a TCP FastCGI protocol fixture and an OTLP
trace collector. It retains the 31 request outcomes and 48 decoded spans from
Commit 06, then asserts exact request/attempt/histogram/body-byte totals, zero
remaining active requests/attempts, one TLS handshake for multiplexed HTTP/2,
available dispatcher health, no series overflow and no synthetic secret canary
in metrics. Retry, reset, WebSocket, keep-alive and header-policy tests remain.

Native Linux and Apple Silicon macOS live runs passed. The optional
`--container-image` path also passed in rootless Podman using a locally available
openSUSE Tumbleweed runtime image with the tested binary mounted read-only. It
uses host networking for the loopback fixtures, no image pull and a private test
directory. This proves container execution of the candidate, not all published
container packages. Native Apple Silicon macOS 27.0.1 (26A434) metrics tests
passed 48 cases (the Linux RSS
subprocess test is platform-specific); the token-reader follow-up passed the
macOS all-feature observability suite as well.

Native Windows execution passed on the shared Windows x86_64 development guest
(OS build 26300.9711), using Rust 1.99.1/MSVC, a separate Fluxheim toolchain/cache,
and the same candidate sources. The original archived baseline plus the explicit
working-tree overlay and subsequent changed files were transferred, not an older
checkout silently substituted for the candidate. Results:

- Metrics: 48 tests; native server with PHP/rustls/load balancing: 539 tests.
- Observability all features: 51 tests plus the compile-fail documentation test,
  including the canonical-token and unpolled-connection cancellation regressions.
- Windows security: 11 tests; filesystem trust: 19 tests, including protected ACL,
  reparse/junction, retained-handle and confidential-file checks.
- Actual Windows executable: the same HTTP/1.1, TLS HTTP/2, FastCGI, retry,
  cancellation, WebSocket and exact-metrics smoke passed. Its Python origin can
  report a connection reset during intentionally aborted requests; all required
  assertions and process exit checks still passed.

Native logs are retained locally outside Git. No shared toolchain, global PATH,
VM boot/security policy or another project's source was changed. This guest is
development infrastructure, not a fresh official release builder; its results
do not establish clean-default Windows or Windows Server qualification.

## Native Windows Discovery: Canonical Token Paths

The first native Windows metrics run failed while inspecting a canonical token
path: the metrics-specific parent walker tried to inspect the bare extended
drive prefix before its root separator. The token test failed with OS error 1;
eight subsequent tests failed because their shared test lock had been poisoned.
The same token test reproduced on unchanged review base `b563894556fa`, so this
was a pre-existing runtime issue, not a regression from the new counters.

The metrics reader now uses the existing shared configuration path inspector,
as the admin reader already does. That helper rejects drive-relative Windows
paths and detects reparse-point components. The subsequent retained-handle ACL
and confidential-file checks are unchanged. No filesystem errors are ignored
and no permissions policy is relaxed. Added tests cover canonical token loading
and continued rejection of symlinked parents. Final observability all-feature
tests passed 53 cases plus the compile-fail documentation test on Linux; the corrected
Windows metrics suite passed all 48 cases.

The broader Windows run also exposed three PHP test-fixture assumptions: two
expected non-canonical script paths, and a spool test used a checkout directory
with unsuitable inherited ACLs and expected Unix-style immediate unlinking.
The tests now compare canonical paths and use the existing protected shared test
root. Unix still requires immediate unlink; Windows requires one live
delete-on-close entry that cannot be reopened, then no entries after dropping
the final handle. PHP runtime behavior and permissions checks did not change.
The corrected server suite passed on both Linux and Windows without skips.

## Remaining Gates

- PromQL examples specify aggregation/reset/quantile semantics; actual backend
  ingestion, dashboard queries/imports and Grafana/SigNoz rendering remain the
  required Commit 10 integration gate, not a claimed result here.
- Full per-backend active-health and certificate-expiry panels remain explicitly
  unavailable; passive event counts are not substitutes. Trace-export health and
  outage/recovery improvements belong to Commit 08.
- Real PHP interpreter/database integration, final extracted archives, release
  reproducibility and all native platform qualification remain later gates.
- The local Windows infrastructure note is ignored and unchanged. A dedicated
  clean VM and release-helper integration are planned in Commit 07A, not built
  by this checkpoint. Existing development-VM evidence must not be described as
  production-default Windows security-policy qualification.

## CodeQL Command-Boundary Follow-Up

Review base: `78160020312e3149fd255d4040d1d3f105922888`, for which the user
reported a clean Critical/High/Medium pentest. GitHub subsequently reported
command-line alerts 398 (Python container smoke) and 399 (Rust RSS self-test).
The Python SARIF trace specifically follows `--container-image` into Podman;
the native `--binary` interface is not the reported flow.

The Linux RSS child now executes the fixed `/proc/self/exe` reference instead
of discovering and reopening an executable pathname. The test remains a fresh
subprocess with the same stress workload and memory assertions. The container
smoke validates a bounded image-reference alphabet before any fixture setup,
revalidates at command construction, and terminates Podman options with `--`
before the image. Arguments remain separate, shell-free values, and image pulls
remain disabled. No alert suppressions or security-check relaxations were added.

Six new Python regression tests cover accepted registry/tag/digest forms,
leading options, shell metacharacters, whitespace, control/non-ASCII characters,
length limits, early failure, native path argument boundaries and the Podman
separator. These tests run in the existing Linux/macOS/Windows correlation jobs.
Local tests passed, as did all seven bounded-metric tests, strict
observability/PHP-profile Clippy, formatting and documentation-link checks.
The actual native and rootless Podman HTTP/1.1, TLS HTTP/2, FastCGI, retry,
cancellation, WebSocket and exact-metrics smoke passed with the updated command
builder. RSS remained 31,637,504 bytes after warm-up and subsequent churn.

This follow-up changes test tooling, its CI wiring and evidence only, not the
production runtime or dependency graph. Native Windows/macOS execution of the
new Python unit tests and closure of the alerts require the new GitHub run;
the previous analysis is not proof of closure.

### Remaining Python Alert And Windows Test Follow-Up

GitHub's analysis of `ffef17e1` cleared Rust alert 399, but Python alert 398
remained: the SARIF flow still followed the image argument through the
alphabet validator. The smoke now accepts only the tested
`registry.opensuse.org/opensuse/tumbleweed:latest` runtime and returns that
literal from the command-boundary validator, rather than forwarding input.
Both CLI and direct helper calls reject other images. Podman's `--` separator,
shell-free argv and `--pull=never` remain in place. This restricts test fixture
selection; it does not authenticate local image contents or change production
container packaging.

The same CI run exposed a Windows command-test failure because host-native
`Path` formatting produced backslashes in Linux container arguments. Container
paths now use POSIX formatting, while native Windows arguments are unchanged.
Explicit `PureWindowsPath` tests cover both behaviors on every test host;
this does not claim support for running this host-network Podman smoke on Windows.

Validation: all nine command-boundary tests, the native Linux live smoke,
the rootless Podman live smoke, documentation links and diff checks passed.
Both live smokes include HTTP/1.1, TLS HTTP/2, FastCGI, retry, cancellation,
WebSocket and exact operational-metric checks. Native Windows/macOS CI and
CodeQL confirmation for this follow-up remain pending. No production Rust or
dependency changes were needed.
