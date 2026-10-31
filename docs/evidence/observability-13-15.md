# Documentation And Native Balancing Checkpoint

Local qualification: 2026-10-31. This record covers the documentation checkpoint
and implemented corrections through Commit 15, starting after
`5b2ae83b05698cf225384ead97370a1b7cda241f`. It is not release acceptance.
The website remains outside this repository checkpoint.

## Delivered

- Feature-oriented README navigation, per-functionality guides, option references,
  a supported-header index, runnable examples and code-to-documentation checks.
- Native load-balancer retry enforcement: bounded distinct-member attempts,
  method/body eligibility, shared retry budgets and cancellation-safe permits.
- Native HTTP/1.1 and HTTP/2 response-header latency samples for weighted
  least-time selection and passive-health thresholds. Body transfer, queueing,
  cache hits and tunnel lifetime do not become upstream latency samples.
- Thirty-second stale-sample resampling, bounded arithmetic and retained
  unknown-versus-historical status semantics. Existing health floors remain intact.
- Previously qualified Wasm configuration/file-contract corrections and the
  Wasmtime 50.0.1 dependency remediation, with their regression coverage retained.
- Cross-platform test-fixture corrections: bounded FastCGI half-close/drain and
  canonical Windows PHP metrics roots. No production PHP security policy was
  weakened to make these fixtures pass.

The [load-balancer guide](../guides/load-balancer.md) defines the precise runtime
contract, including failure, retry, recovery and measurement limitations.

## Verification

| Check | Local result |
| --- | --- |
| Locked workspace suite on Linux | Passed |
| Combined Wasm/PHP/load-balancer/rustls server suite, Linux x86_64 | 682 passed |
| Same combined server suite, Windows x86_64 | 677 passed |
| Same combined server suite, macOS Apple Silicon | 680 passed on each of three consecutive runs; one environment-specific test excluded as described below |
| Load-balancer library | Linux/macOS 157 passed; Windows 155 passed |
| Python suite | 394 tests, two platform-dependent skips |
| Clippy, combined server features and minimal server features | Passed with warnings denied |
| Documentation links, formatting, modularity and release metadata | Passed |
| Production RustSec audit and cargo-deny | Passed; 449 locked dependencies, no known advisories |

Live built-binary tests passed on Linux, Windows and macOS. They exercise active
health/recovery, disabled/enabled retries, shared retry budgets, controlled
fast/slow origins, swapped latency, stale-member resampling, threshold-disabled
behavior, passive ejection and exclusion of body-transfer time.

A fresh non-root Wolfi load-balancer image passed the same retry/latency cases
and graceful shutdown checks. Its local image ID is
`sha256:29108423c9499d19474a8e9ff4a9ddc803d1e977b482413bbd393460539453a0`.
Subsequent edits to that checkpoint were test fixtures, test organization,
documentation and publication exclusions, not production runtime changes.

## Qualifications And Publication

The macOS builder does not give the connection-refused behavior required by
`operational_refused_connection_is_not_a_protocol_error`. It was excluded locally,
not weakened or skipped in CI. The combined PHP suite also exposed fixture
portability failures; corrected fixtures were rerun on the native platforms.

Native Linux ARM64 qualification is still required for the final release
candidate. Earlier native archives are not evidence for these runtime changes;
final archives, cumulative pentesting and exact-commit GitHub CI/CodeQL remain
release gates. A passing local suite is not a security certification.

The unresolved numbered correction queue, private reproduction material, VM
state and raw local qualification logs are excluded from Git and container
contexts. Public guides retain truthful behavior and deployment limitations;
their presence does not imply every outstanding correction is complete.

## Retry Budget Review Follow-Up

The review of this checkpoint identified implicit unlimited pool retry admission
when `budget_per_window` was omitted or zero. Enabled retries with positive
`max_retries` now require an explicit budget from 1 to 1000000. Runtime admission
also rejects zero and invalid budgets for programmatic callers that bypass
configuration validation. Disabled retries and zero additional attempts retain
their existing defaults.

Regression coverage checks root/vhost/route validation, budget boundaries,
expiry, concurrency, cancellation/refunds and repeated HTTP/1.1/HTTP/2 status
and transport failures with zero budget. Documentation distinguishes per-pool
budgets from a process-wide limit; no global retry limiter is claimed.

Follow-up local verification on Linux: locked workspace passed, combined server
683 passed, load-balancer library 157 passed, Python suite 394 tests with two
platform-dependent skips, and strict Clippy/formatting/documentation checks
passed. Native Windows/macOS and exact-commit CI remain to be rerun for this
follow-up; the earlier platform results above do not qualify the changed source.
The built-server smoke also passed missing/zero budget rejection before origin
contact, positive-budget exhaustion, retry recovery and all latency scenarios.

## CI Portability Follow-Up

The first GitHub run for the retry-budget follow-up exposed test portability
and documentation-contract failures. The corrections preserve production path
validation and do not remove negative tests:

- Raw TOML guide tests resolve their process paths into the existing protected
  test directory, as the real configuration loader does for configuration files.
- Executable Markdown/TOML examples retain LF on Windows checkout. An isolated
  Git regression test verifies this with `core.autocrlf=true` and a CRLF control.
- The privacy smoke accepts refusal or timeout from its reserved, non-listening
  metrics socket; an accepted connection still fails the test.
- The Wasm release validator checks the current guide wording for the same
  deployment boundaries rather than requiring removed headings.
- Wasm file tests own their temporary root and use the checked Cargo test-child
  launcher. File opening repeats the approved-root boundary check locally.
- Admission tests hold the actual slot and verify rejection, release and recovery,
  replacing a scheduler-dependent overlap assumption without changing admission
  behavior. Test-only accessors are confined to the existing test module.

Linux verification passed: locked workspace, 683 combined server tests, 59
all-feature Wasm tests, 395 Python tests (two platform-dependent skips), strict
Clippy, formatting, documentation links, modularity and release metadata checks.
RustSec and cargo-deny reported no advisories across 449 locked dependencies.

Native macOS configuration (521 tests), all-feature Wasm (59 tests), related
server tests (43 tests), LF checkout and privacy helper tests passed.
Built-binary privacy and retry/latency smoke
checks passed, including missing/zero retry budget rejection. Native tests use
the established non-symlink temporary directory; the default macOS `/var`
symlink is intentionally not accepted by the secure plugin-path policy.

Native Windows passed the locked workspace, including all 560 configuration
tests, the combined server suite (678 tests), and all-feature Wasm (58 tests).
LF checkout and privacy helper tests passed, followed by built-binary privacy
and retry/latency smoke checks, including missing/zero retry budget rejection.

The owner approved dismissal of two Python stored-secret alerts after their
data flows were verified to contain only checked-in smoke-test policy settings,
not credentials. Rust alert follow-ups still require the next exact-commit
GitHub scan; local passing tests do not establish that those alerts are closed.

## Runner Follow-Up

The subsequent scan of `50c634a1` completed with no open code-scanning alerts.
Its CI run exposed three further fixture/profile mismatches:

- The gRPC characterization loaded a snapshot with relative process paths,
  depending on the checkout's Windows permissions. It now loads the example
  through the real file loader from the protected test root and checks all three
  resolved process paths using canonical parents, including Windows verbatim
  path equivalence.
- The live latency smoke assumed one new sample must reverse an EWMA ranking.
  It now requires three consecutive selections of the expected origin within
  twelve attempts and ten seconds, before stale-sample reset could mask a
  failure. Regression tests reject stuck/alternating selection, late convergence
  and unexpected responses. The separate stale-resampling check remains.
- CI now enables `acme-client` when checking the two managed-ACME templates;
  default features do not include ACME. Template consent settings are unchanged.

Linux verification passed: locked workspace, 683 combined server tests, strict
Clippy, 399 Python tests (two platform skips), and the full load-balancer smoke.
The five ACME guide configuration tests and both ACME-enabled CLI template checks
passed. For the latter, local fixture copies used private process paths because
this workstation's `/run/fluxheim` belongs to another service account. The exact
unmodified CI example matrix could not run under those host permissions.

The full macOS native parity smoke passed, covering static/proxy/TLS, admin,
load balancing, memory/disk cache and local observability. Its optional external
Prometheus/Jaeger checks were skipped because those collectors were not running.
The final gRPC fixture assertion also passed natively on macOS.

One Windows workspace attempt encountered an access-denied error in the unchanged
snapshot migration test. Twenty isolated repeats and the complete 53-test
snapshot suite passed without reproducing it. No snapshot code or security
policy was changed; this remains an observation, not a claimed remediation.

The subsequent Windows workspace run passed, including 553 default server
tests, followed by 678 combined server tests and the live privacy/retry/latency
checks. All nine retry/latency Python fixture tests passed natively. The Linux
container-argument test uses `PurePosixPath` so its mount contract is tested
unchanged on Windows rather than interpreted as a Windows filesystem path.
No production Rust, manifest or lockfile changes are included in this follow-up.

### Native CI follow-up for `75e2aaff`

Code scanning reported no open alerts. The next native CI run exposed two
platform-specific fixture problems:

- macOS used its default symlinked temporary directory for server fixtures.
  CI now creates a private, canonical temporary root before running tests.
  A regression covers symlinked parents, spaces, mode `0700` and unique roots.
  Production path and symlink checks are unchanged.
- The ACME mock accepted sockets from a nonblocking listener but then used
  blocking TLS I/O. Windows preserves the nonblocking mode. The fixture now
  explicitly restores blocking mode while retaining read/write deadlines;
  a delayed-peer regression exercises that setup on every platform.

The reserved, non-listening origin test now asserts macOS's timeout response
and the refusal response on Linux/Windows separately. It keeps the port
reserved, checks the exact event reason and still rejects protocol-error
misclassification. Windows retains the normal connection deadline to allow its
refusal to arrive. No test is skipped for this difference.

Broader native ACME testing also reproduced a production macOS failure when
concurrent operations created the same lock file. Unix lock opening now first
attempts exclusive creation, then opens the existing lock only on `EEXIST`.
All three lock modes retain handle-relative access, `NOFOLLOW`, close-on-exec,
and the original flock behavior. Other errors still fail closed. Regression
tests cover concurrent creation of one inode, private creation permissions,
non-truncation and rejection of a symlink for every lock mode. Windows lock
implementation is unchanged. The macOS ACME suite is now an explicit CI step.

Verification passed:

- Linux locked workspace and 683 combined server tests.
- Linux ACME all-feature suite: 101 passed, one existing privileged test ignored.
- macOS combined server suite: 682 passed with no exclusions.
- macOS ACME suite: 101 passed; the previously failing concurrent certificate
  installation also passed twenty consecutive isolated runs.
- Full macOS static/proxy/TLS/admin/load-balancer/memory-and-disk-cache/local
  observability parity smoke. Optional external Prometheus and Jaeger checks
  were skipped because no external collectors were running.
- Windows full native runtime parity smoke, including 84 ACME tests, followed
  by all 678 combined server tests.
- 400 Python tests (two platform skips), strict ACME/server Clippy, formatting,
  Windows policy validators and diff checks.
- Cached RustSec audit: no findings across 449 locked dependencies; no
  dependency changes are included.

The dedicated Windows VM was shut down normally after testing. These local
results do not replace a successful GitHub rerun after pushing the corrections.

### CI harness follow-up for `2f9196fc`

The previous native failures passed in GitHub. The next run reached three later
qualification failures, with no open code-scanning alerts:

- Three Windows steps contained PowerShell but inherited the job's Bash
  default. They now explicitly select `pwsh`; a regression checks all steps
  containing PowerShell control syntax, not only the originally failing step.
- The macOS runner selected Python 3.15, outside the wheel lock's reviewed
  CPython 3.10-3.14 targets. Both native jobs now select Python 3.14 through a
  commit-pinned setup action before creating their virtual environments.
  Hash checking remains mandatory; no dependency version or hash was changed.
- Pebble reused a previously validated authorization, so successful certificate
  issuance did not perform the fresh challenge required by this smoke. Each
  entry-point/profile combination now uses a distinct test issuer/account while
  retaining the same CA, domain, vhost and certificate store. The fixture always
  reuses eligible authorizations, making accidental account reuse detectable.
  All four distinct successful HTTP-01 validations are still mandatory.

Native Windows testing additionally exposed a connection timeout while a
logging fixture started. Readiness now retries only TCP connection establishment
within the existing bounded startup window; it never retries an HTTP request.
Regression tests cover refusal, timeout, child exit, deadline and other errors.

The rebuilt full and PHP Wolfi images passed the complete packaged renewal smoke
twice under Podman, including four distinct HTTP-01 validations on each run.
All 407 Python tests passed (two platform skips), as did the Windows release
policy validator and cached RustSec audit of 449 dependencies. Python 3.14 wheel
downloads for macOS ARM64 and Windows x64 passed the unchanged hash lock. Native
macOS Python 3.14 installation, nine API contract tests and the live operational
API smoke passed. No Rust source, Cargo manifest, lockfile or production
container definition changes are included.

The logging smoke passed all eight live scenarios on Linux, macOS and native
Windows. The complete Windows protected-log-rotation step also passed, including
metrics, tracing, collector-guide, admin, snapshot, CLI and log-rotation checks,
followed by the privacy smoke. This local Windows VM uses Python 3.13.15; Python
3.14 wheel availability was checked separately, and the GitHub job selects 3.14.
The Windows live load-balancer smoke also passed every retry and latency case.
