# Observability Commit 04: Bounded Logging

Base: `27c752a2341297ba10c055eaec234479f42714dc`. The user accepted Commit 03's
documented durability limitation, reported GitHub green and authorized this
checkpoint. This implementation still requires incremental pentest, exact-SHA
GitHub/CodeQL and explicit approval before Commit 05.

## Runtime Contract

All runtime/library calls through `log` now reach a bounded adapter, not
env_logger's synchronous writer. env_logger remains the target/level/message-regex
matcher. The global maximum level remains the configured filter's maximum, so
disabled debug/trace macros retain their existing fast path. No tracing subscriber
or log-to-tracing bridge is installed, and no request-completion producer is added.
Native access completion and span export remain later checkpoints.

The three typed lanes from Commit 03 remain unchanged. A fourth **legacy** lane
cannot spend typed ordinary/security/audit quota or credits. `log` targets named
`security` or `audit` do not grant access to protected typed capacity.

| Resource | Enforced legacy limit |
| --- | --- |
| Outstanding records | 128 total including captures, queued and in-flight output |
| Concurrent producers | 8; atomic nonblocking admission before formatting |
| Message / target | 4096 / 1024 UTF-8 bytes, fixed storage, reject overflow |
| Encoded output | 8192 bytes including newline, fixed worker buffer |
| Workers | 1 legacy + 3 existing typed workers, created once at startup |
| Queue payload | `128 * size_of::<Queued>()`, exposed in status; excludes channel bookkeeping/stacks |
| Shutdown | Shared 500 ms total wait for all four workers, no unbounded join |

This replaces the preliminary two-worker proposal in Commit 01. Isolation now
needs three typed workers plus one legacy worker. Counts/bytes are deliberately
below the proposed 4096-record/8 MiB default; no proposed queue configuration keys
are implemented. Each producer may hold bounded stack copies and a bounded
regex-matcher message allocation. Worker stacks and channel bookkeeping add
fixed platform-dependent overhead; queue bytes are not an RSS quota.

Metadata rejection happens before capture. Admitted callers format into bounded
storage once, then match message regex against that bounded copy. Full capacity,
producer contention, recursion and unavailable workers return immediately without
formatting. No caller performs sink I/O. JSON/text encoding, writes and flushes
run only in the worker. Oversized encoded output is discarded without disabling
the sink. Text escapes control characters, quotes and backslashes; JSON retains
the existing timestamp/level/target/message schema. Capture timestamps remain UTC
RFC3339 milliseconds. The already-locked jiff dependency supplies the same time
formatter used internally by env_logger; no package versions change.

Rust `Display` code is trusted in-process code, not a sandbox: the adapter caps
concurrent calls and output, but cannot interrupt arbitrary formatter computation,
allocations or I/O inside custom implementations. Precomputed arguments are also
outside the adapter. Unwinding releases credits and counts capture panics. Worker
reentrant logs are suppressed; panicking writers terminate their lane and queued
RAII records account for losses. No unsafe code or per-record tasks are added.

## Lifecycle And Visibility

Authenticated `GET /_fluxheim/status` gains `legacy_logging`, null before logging
initialization. It reports capacities, accepted/filtered/oversized records, full
queue, busy producers, recursion, unavailability, capture/worker panics, sink
errors, written/discarded/pending records, active producers and worker liveness.
Counters saturate; active gauges are bounded. Snapshots are approximate during
concurrent updates. An oversized encoded record is both oversized and discarded;
do not sum all counters as disjoint categories. Facade-level suppression before
the logger is not counted as a submitted record.

`written` means successful write and flush, not durable storage. Write/flush error
or worker panic stops that lane, counts queued discards, and prevents new admission.
There is no recursive error logging, fallback sink or retry loop. `log::flush()`
does not block; the runtime guard owns bounded draining. Cancelling/dropping an
owner closes admission without joining a blocked writer. Pending output may be
lost on deadline/process exit; a blocked OS write cannot be safely cancelled.

Startup fails on secure-open, worker-spawn or global logger installation failure.
Partially initialized workers close admission. Repeated initialization fails;
reload does not spawn workers or swap format/filter/file ownership. No public
request can reconfigure this process-global lifecycle. File handle validation is
unchanged; rotation/reopen is Commit 05. Cross-lane ordering is unspecified and
all workers can depend on the same OS sink. CLI output, pre-initialization parser
diagnostics and panic hooks are not routed through this runtime adapter.

This is bounded **best-effort** logging. It does not make legacy raw messages
secret-free, audit output durable, or compromised processes trustworthy. Typed
events keep their stricter finite schema. Existing audit admission, unavailable
mutation errors and ambiguous completion behavior remain unchanged.

## Permanent Proof

- [Dispatcher tests](../../src/runtime_log_dispatch_tests.rs): 32,000 submissions
  with a blocked writer, eight blocked formatters, formatting/worker recursion,
  formatter unwind, owner cancellation, closed/failed/panicking sinks, shutdown
  deadlines, bounded regex filtering, Unicode properties, byte overflow,
  schema fixture and preinstalled-logger startup failure.
- [Live pipe smoke](../../scripts/smoke_operational_backpressure.py): retains both
  Commit 03 scenarios and adds two with normal INFO logging enabled from startup.
  A prefilled stderr pipe receives 1,200 public host denials and 1,200 admin auth
  failures. The legacy lane saturates while public serving and authenticated
  audit admission still work. Audit saturation still rejects mutation before
  state changes; draining restores delivery; permanently blocked output cannot
  prevent bounded shutdown. Auth throttling is disabled only in this generated
  fixture to let the test reach legacy queue capacity without locking out status.
- Existing seven JSON/text/filter/stdout/file scenarios and admin/snapshot/cache
  regressions remain required; tests are not weakened to avoid sink backpressure.

## Local Qualification

2026-10-23, Linux x86_64, Rust 1.99.1. Commands completed successfully unless
explicitly marked blocked:

- `cargo test --locked --workspace`: 1,824 successful executions including the
  isolated subprocess initialization tests; one existing privileged ACME test ignored.
- `cargo test --locked -p fluxheim --lib --no-default-features --features profile-observability`:
  262 passed. Privacy profile: 175 passed. Observability all features: 47 plus
  the compile-fail doc test. Expanded native server suite: 586 passed.
- Workspace all-target Clippy with warnings denied; no-default-features check;
  locked fuzz metadata; RustSec audit (449 dependencies) and cargo-deny policies.
- Seven output/filter smokes; four real pipe scenarios on debug and release
  binaries; admin listener, live snapshot lifecycle, proxy-cache and load-balancer
  smokes. Existing rollback/admission protections remain covered.
- Documentation layout/links, formatting, modularity and Windows release-script
  validator passed. Native Windows cross-check of the application was **blocked**
  by this Linux environment's missing MSVC `lib.exe`, not counted as a pass.

Windows CI runs the workspace dispatcher tests and native parity smoke. macOS CI
now explicitly runs dispatcher tests and both live output/pipe scripts after a
fresh observability build. Pipe fixtures use short socket paths for macOS. These
native runs are pending, not inferred from Linux or from a compilation check.
Windows real blocked-pipe/performance qualification remains a native-host gap;
mock blocked-writer tests do not substitute for native OS pipe evidence.

## Performance Comparison

[Sample summaries and binary identities](observability-04-linux.json) compare the
accepted base worktree with this development build on the same host. Each ran
three alternating off/on pairs of 10,000 loopback proxy requests, eight clients
and two runtime threads, using `scripts/observability_baseline.py`. These are
optimized `profile-observability` builds, not signed release artifacts. Base SHA
and candidate dirty-worktree status plus binary SHA256 identify the inputs;
cached embedded version strings alone do not distinguish development builds.

| Mode / build | Median req/s | Median p95 / p99 (ms) | Max peak RSS | Median CPU / 10k | Max shutdown |
| --- | --- | --- | --- | --- | --- |
| Off / base | 3012 | 3.40 / 3.83 | 12.61 MiB | 1.57 s | 1.015 s |
| Off / candidate | 3027 | 3.39 / 3.85 | 13.67 MiB | 1.56 s | 1.015 s |
| On / base | 3008 | 3.36 / 3.78 | 13.46 MiB | 1.58 s | 1.015 s |
| On / candidate | 3045 | 3.35 / 3.80 | 14.36 MiB | 1.58 s | 1.015 s |

No Commit 01 review threshold was crossed: enabled throughput +1.2%, p99 about
+0.02 ms, CPU unchanged, RSS +0.9 MiB (below queue budgets +16 MiB). Scheduling
noise and a local Python origin/client limit these results. This benchmark still
has no native access-completion producer, so it measures current runtime/export
overhead, not future per-request logging cost. Native performance remains pending.

The separate **saturated sink** release smoke reported 128 pending legacy records,
664,576 queue-payload bytes, 1,077 queue-full rejections and zero sink writes before
draining. One hundred healthy requests while blocked had p95/p99 0.24/0.39 ms
(recovery scenario) and 0.23/0.30 ms (permanent blockage). Peak RSS was 13.50/13.61
MiB; process CPU 0.08/0.09 s at that sample. These are distinct static-serving
diagnostics, not apples-to-apples proxy benchmark speedups. Shutdown completed
within the smoke's six-second process deadline with the logging guard capped at
500 ms. The typed-only prior regressions also passed.

One cache smoke attempt overlapped another profile's binary rebuild; its CLI
reported missing cache features. Re-running it alone passed. Switching the shared
Cargo release cache between worktrees also reused a stale observability artifact;
cleaning only that package's release artifacts and rebuilding passed. Neither
failure was hidden by loosening assertions or filesystem checks.
