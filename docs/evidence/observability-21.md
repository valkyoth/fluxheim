# Commit 21: Slice Upstream Policy

Base: `cd5bc4561cb542cfd575e04885fccb1d62be9e35`.

## Scope

Commit 14 already routed slice attempts through pool selection and the shared
retry/latency dispatcher. This correction removes the remaining discovery-only
cache capability restriction when load balancing is compiled. It does not add a
second retry or selection implementation, change cache keys, or relax strong
ETag, body-size, response-admission or filesystem checks.

Live HTTP discovery also reproduced a startup failure: synchronous pool
construction inside Tokio polled asynchronous discovery once and rejected its
pending result. Dynamic initialization now runs its existing synchronous
discovery implementation on a joined, scoped thread outside the entered
reactor. There is no detached bootstrap task or nested Tokio runtime. Thread
creation/discovery failures propagate; periodic refresh remains asynchronous.
Static construction is unchanged. This API remains synchronous; platform file
and DNS operations retain their existing blocking characteristics, while HTTP
discovery retains its five-second timeout and bounded response parsing.

Tokio's multi-thread runtime feature is added only to the load-balancer's test
dependencies to exercise both runtime types. No locked package/version changes.

## Regression Coverage

- Discovery-only capability test failed before the correction. Minimal builds
  must still reject this capability without compiled load-balancer support.
- Slice attempts skip drained, disabled and forced-down primary members, use
  backups, recover after resume, record latency and release in-flight slots.
- Saturated pools time out without contacting static members or spending retry
  budget; cancellation releases selected-member admission.
- Existing slice retry tests cover shared pool budget, disabled retries,
  oversized replies and fallback without resetting the budget.
- Bootstrap tests exercise file and DNS membership inside current-thread and
  multi-thread Tokio runtimes; missing files fail closed.
- Live counted HTTP origins cover drain, active-health all-down/recovery,
  discovery replacement/removal, collapsed concurrent fills and conflicting
  replica validators. File discovery is exercised in native mode; HTTP
  discovery is also exercised in the non-root container.
- Existing persistent-slice qualification retains memory/filesystem/bin restart
  and variant checks. New live checks are included in Linux/macOS/Windows CI.

## Qualification

Completed on 2026-11-13 using Rust 1.99.1:

| Check | Result |
| --- | --- |
| Linux locked workspace suite | Passed |
| Linux server with Rustls, load balancing, Wasm and PHP | 729 passed |
| Linux server with OpenSSL and load balancing | 624 passed |
| Linux load-balancer Rustls suite | 186 passed |
| macOS ARM64 load balancer / server | 186 / 627 passed |
| Windows x86_64 load balancer / server | 184 / 625 passed |
| Feature-minimal discovery capability rejection | Passed |
| Strict server/load-balancer Clippy and macOS server Clippy | Passed |
| Live upstream scenarios on Linux, macOS and Windows | Health/drain, HTTP and file discovery, concurrent fills, replica mismatch passed |
| Non-root Podman upstream scenarios | Health/drain, HTTP discovery, concurrent fills, replica mismatch passed |
| Slice persistence smoke | Five memory/filesystem/bin cases passed natively on all three systems and in Podman |
| Python slice fixture / cache guide tests | 3 new, 5 existing slice, 11 cache tests passed |
| Documentation layout, links, formatting and diff checks | Passed |
| RustSec and cargo-deny | 449 locked dependencies; no advisory failures; policy passed |

Container image tested:
`sha256:adf7b273fef0eca59c691cbdfd3bd3c8ed59131ae8328b75a1ab0d85e79465bf`.
The dedicated Windows VM used the normal non-administrator build account; no
shared project toolchain or machine settings were changed. Native archives and
Linux ARM64 were not rebuilt/requalified for this correction and remain final
release gates. Independent pentest and exact-commit GitHub acceptance remain
pending; this is not release qualification or an absence-of-bugs claim.

Fresh cached slices are not purged by membership updates. Already selected
attempts can finish on a member removed during the exchange. Every composed
slice still requires matching strong ETag, total and optional Last-Modified.
Initial fill attempts and ordinary fallback are not charged as retries; operators
must size slice, concurrency, rate and per-pool retry limits together.

## CI Follow-up

The owner supplied a clean Critical/High-threshold pentest for `68febd91`.
CodeQL and the native Windows/macOS and Linux archive jobs also passed at that
commit. Rust CI run `43394232442` failed in the Linux localhost sequence:
`smoke_proxy_cache.sh` rebuilt the shared debug binary without load-balancer
support, then the slice-upstream fixture correctly rejected that binary. The
workflow now explicitly builds the load-balancer/ACME profile immediately before
running the slice-upstream fixture. No runtime or fixture assertion is weakened.

With owner approval, optimized release matrices, archive builds/tests, SBOM and
reproducibility work now run on tags, manual full checkpoints and relevant
packaging/dependency/toolchain changes. Diff/history uncertainty selects full
qualification. Native code tests, live checks, audits and the separate CodeQL
workflow remain on every commit. Skipped qualification is not release approval;
the runbook requires a full exact-candidate run before tagging and successful
tag qualification before publication.

Follow-up verification: the old cache-profile/slice sequence reproduced the
reported failure locally; rebuilding the explicit profile passed all four live
slice scenarios. The unchanged broad cache smoke passed on rerun after one
initial disk-lookup assertion failure; no cache assertion was relaxed. Ten new
CI policy/workflow tests passed on Python 3.13 and 3.14, along with collector CI
(2), container-refresh policy (35), development scope (7), documentation layout
(28), build-guide (9), archive regression (20), slice fixture (3), and operational
contract/workflow tests (9, using the hash-locked Python environment). Python
compilation, documentation links and diff validation passed. No Rust source,
Cargo manifest or lockfile changed in this follow-up. GitHub execution of the
new gating logic remains required after push.

### Qualification Trigger Correction

Retest of `68febd91..e9bb4b6e` identified a Medium policy omission: the shared
archive generator, qualification selector and Rust CI workflow did not trigger
full qualification when changed. All three exact paths are now included.
Regression cases reproduced the omissions before the correction and pass for
both push and pull-request comparisons afterward. Runtime-only changes still
select development checks; tags, manual dispatch and uncertain history still
force full qualification. This policy correction itself requires a full run.

Verification: 11 qualification tests, 2 collector-CI tests, 3 slice fixture tests,
20 archive regressions and 28 documentation-layout tests passed, along with
Python compilation, documentation links and diff checks. No Rust, Cargo or
CodeQL configuration changed. GitHub qualification and independent retest of
this correction remain pending.
