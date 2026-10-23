# Commit 04: Fatal Diagnostics Before Abort

Review base: `a504b744d15b838af5371bff80191f7767b40e98`.
Follow-up: [watchdog and critical-exit remediation](observability-04-watchdog.md)
corrects the initial implementation's unbounded diagnostic-stall regression.

## Finding And Fix

The pentest correctly identified a regression: ordinary `log::error!` followed
by `process::abort()` could lose the fatal diagnostic in an asynchronous queue.
Abort does not run the logging guard; queue flushing cannot recover a rejected
record, dead worker or full sink.

All explicit invariant aborts in the runtime, native server, load balancer, TLS
and Wasm crates now use `fluxheim_common::fatal::abort(Reason)`. The finite reason
vocabulary contains no dynamic strings, request fields, tokens or raw errors.
Existing supplementary legacy errors retain their previous behavior, but are no
longer the only diagnostic. The fail-stop conditions and authorization logic are
unchanged. Previously silent load-balancer and Wasm aborts also receive codes.
No abort behavior is changed into panic/unwind or poisoned-state recovery.

With its watchdog initialized, the helper attempts a synchronous stderr write before aborting, independently
of the log facade, level/regex filters, worker liveness and all queue capacities.
An optional `logging.crash_file` is opened before serving: private regular file,
trusted parents, no symlinks/reparse points, existing confidential ACL checks on
Windows, mode 0600 on Unix, no truncation. Handle identity checks prevent aliasing
the ordinary log, including a hard link, before a non-append log can truncate it.
Configured sink failure rejects startup. The retained file uses its own mutex,
recovers that mutex's poison only to report and terminate, appends, and calls
`sync_data()`. I/O errors attempt stderr instead. No diagnostic failure resumes
the failed operation. Reload classifies crash-sink changes as process upgrades;
snapshot-safe field copying cannot change the destination.

## Explicit Limits

- This is a synchronous write attempt, not a tamper-proof or durable audit journal.
- A separate, prestarted watchdog forces abort after its 250 ms diagnostic grace
  period following wake-up, plus OS scheduling latency. It never acquires sink
  locks. Before watchdog initialization, diagnostics are skipped for immediate
  termination. The original unbounded stall behavior is no longer accepted.
- File sync does not establish power-loss-safe directory creation, off-host
  replication, WORM retention or protection from same-UID/root compromise.
- Process kill, memory corruption, external library aborts, OOM, panic hooks and
  hardware failure are not converted into guaranteed diagnostics.
- The file handle remains open until exit. It is not a rotated ordinary sink;
  operators manage retention and restart after relocating it.
- Compile-time privacy mode disallows file configuration; fixed stderr reason
  codes remain enabled even with ordinary logging disabled.
- Commit 03 audit reservations and the explicitly accepted non-durable audit
  contract remain unchanged. This does not turn queue admission into persistence.

## Regression Coverage

- Subprocesses really abort after a full legacy queue, a dead worker, disabled
  logging, no logger installation, normal startup, and a failed crash-file write.
  The parent checks reason bytes after exit and enforces a bounded test deadline.
  A blocked ordinary writer cannot prevent the separate crash-file record.
- A real poisoned admin-auth-throttle lock emits its exact finite reason with
  logging off and still aborts instead of returning inconsistent security state.
- Existing crash content is preserved; duplicate sink installation is rejected;
  failed file writes fall back to stderr, without leaking a secret canary.
- Unsafe startup paths, directories, absent parents, file aliasing, public Unix
  permissions, symlinks and FIFOs are rejected. Alias rejection does not truncate
  earlier crash evidence or install logging workers.
- Configuration defaults, relative resolution, path validation, privacy policy
  and process-upgrade classification have permanent tests.
- A source inventory test rejects direct runtime `process::abort()` calls outside
  the shared fatal helper, preventing recurrence when new abort sites are added.

Native Windows/macOS execution and exact-SHA GitHub/CodeQL remain required CI
gates. Linux execution is not a substitute for native ACL and runtime validation.

## Original Local Validation (21451e18)

- Locked workspace suite: 1,835 passing test executions (including subprocess
  harness invocations); one existing privileged ACME test ignored.
- Root observability profile: 270 tests passed; privacy profile: 183 passed.
  Configuration privacy checks also passed.
- Native server with Wasm, PHP, rustls and load-balancer features: 586 passed.
  OpenSSL TLS suite: 27 passed.
- Workspace and Wasm-profile all-target Clippy with warnings denied passed.
- Live binary event smoke: seven scenarios passed, including startup with both
  ordinary and crash files and proof that ordinary traffic leaves the crash file
  empty. Four typed/legacy blocked-pipe recovery/shutdown scenarios also passed.
- Windows cross-compilation of the common fatal helper and configuration passed;
  the full root Windows check stopped because this Linux host lacks MSVC `lib.exe`.
  PowerShell release-policy validation passed; no native Windows execution claimed.
- RustSec audit (449 dependencies), cargo-deny, formatting, documentation links,
  documentation layout, modularity policy and diff integrity passed. No external
  package versions changed; TLS/Wasm only gained an internal common-crate edge.
