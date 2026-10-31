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
