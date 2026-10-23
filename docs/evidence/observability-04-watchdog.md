# Commit 04: Fatal Watchdog And Critical Exits

Review base: `21451e1879b99fb5778fc4f6eb8177ce03d5167f`.

## Confirmed Findings

1. The previous fatal helper could wait indefinitely on Rust's global stderr
   lock when an ordinary worker was blocked writing a full pipe. The optional
   crash file could also stall on its mutex, write or sync, or fall back to that
   same stderr lock. Merely documenting this did not preserve fail-stop behavior.
2. Five immediate exits across stream, UDP, metrics and HTTP proxy listener
   paths still relied solely on asynchronous error records. They skipped the
   logging shutdown guard and could lose the reason for process termination.

## Remediation

One watchdog thread is started before logging workers and before serving, even
with no crash file or with privacy mode. Spawn failure rejects startup. It is
process-global and parked while healthy: no polling, output, queue or per-event
thread creation. The fatal reporter sets an atomic flag and unparks it before
acquiring any diagnostic sink locks. Once awake it waits 250 ms and calls the
raw process abort primitive, without logging or acquiring application locks.
The flag cannot be cleared and concurrent reporters cannot extend the deadline.

If the watchdog is not yet initialized (or initialization failed/is in progress),
reporting is skipped and termination proceeds immediately. No attempt is made to
allocate/spawn a watchdog or wait for initialization from an inconsistent state.
Installing a private sink also ensures the watchdog has started. The existing
secure file opener, ownership/ACL checks, alias checks and privacy policy remain
unchanged.

`fatal::exit(Reason)` preserves the listener paths' status 1 when reporting
completes. The watchdog aborts if reporting or exit stalls. No broad task-supervisor
interface or graceful-drain guarantee is introduced: only the finite failure
reason is attempted independently of the queues. Direct exit inventory now
exempts only the three synchronous CLI entrypoints, where runtime unwinding has
already completed, and the common termination helper.

## Assurance Boundary

The subsequent [core dump deployment fix](observability-04-core-limits.md)
adds zero launcher limits and documents the separate host collector policy.
Watchdog aborts must not be treated as secret-free OS memory dumps.

Fail-stop wins over diagnostic delivery. The watchdog can terminate before a
blocked record reaches storage; neither crash reports nor ordinary audit records
are durable journaling. Its 250 ms grace period starts on watchdog wake-up and
depends on the OS scheduling this thread. Kernel-wide hangs, malicious same-UID
or root code, external kills and hardware failure still require external controls.
High-assurance operators should use a dedicated crash sink, an external supervisor
with a process termination deadline, and an independent durable audit system.
There is no newly claimed military/high-assurance certification or profile.

## Permanent Regressions

- Real child stderr pipe, left unread by the parent: a writer owns Rust's global
  stderr lock while writing 1 MiB. The write does not complete, and captured bytes
  after termination prove it reached and filled the OS pipe. Fatal reporting still
  terminates. The parent kills/reaps a stuck child and fails after a CI-tolerant
  five-second bound; it never drains the pipe to make the test pass.
- The same test covers failed crash-file fallback to full stderr, a held crash-file
  mutex, concurrent fatal callers, early uninitialized abort and early abort with
  blocked stderr. It tests both immediate exit status 1 and watchdog-driven abort
  of a stalled exit. Existing exact reason, file preservation, queue saturation,
  privacy and poisoned-admin-state tests remain enabled.
- Real Fluxheim binary smoke reserves metrics/TCP-stream/UDP ports, starts the
  server with logging disabled and a protected crash file, then checks status 1
  and the precise finite reason. A different startup/config failure cannot pass
  because it would not produce the expected crash record.
- The source inventory rejects both direct runtime aborts and exits. Linux and
  macOS CI run the listener smoke; macOS explicitly runs the common watchdog
  test, and Windows runs it through the native workspace suite.

Native-platform GitHub checks and independent pentest remain acceptance gates.
Stop before Commit 05.

## Local Validation

- Locked workspace: 1,836 passing test executions, including child harnesses;
  one existing privileged ACME test ignored.
- Observability plus TCP-stream/UDP profile: 297 tests passed; privacy profile:
  183 passed. The new common-crate regression exercises eight subprocess scenarios.
- Three live occupied-listener scenarios passed with precise crash-file reasons
  and exit status 1. Seven existing event scenarios and all four typed/legacy
  blocked-pipe recovery/shutdown scenarios also passed.
- Workspace/all-target Clippy with warnings denied, RustSec audit (449 packages),
  cargo-deny, formatting, documentation layout/links, modularity and diff checks
  passed. Only test dependency edges were added; no package versions changed.
- Windows cross-compilation of the common helper and its tests passed; PowerShell release
  validation passed. Native Windows/macOS execution remains pending GitHub CI.
