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
