# Commit 04: CI Portability And Test Boundaries

Review base: `5fe95c58a633f73a07c0327d1001d65562394504`.

## Confirmed Failures

- GitHub run `40010621762`: macOS could not compile the FIFO rejection test
  because rustix does not expose `mkfifoat` on Apple targets. The test now uses
  the absolute macOS `mkfifo` executable, confirms the result is a FIFO, and
  retains the nonblocking rejection assertion. Unix coverage is not skipped.
- The Windows watchdog test expected bytes from a single pending 1 MiB pipe
  write to survive process termination. It now completes one byte before the
  writer handshake, then fills the pipe with small writes while retaining the
  stderr lock. The parent still leaves the pipe unread until termination and
  checks incomplete output, termination deadlines and exact fatal behavior.
- Native macOS execution exposed an additional live-smoke assumption: a bound
  but non-listening upstream can time out instead of refusing connections.
  The fixture releases the selected port before requesting it. It still requires
  HTTP 502, the expected body and the exact `connection_refused` event; port reuse
  cannot silently satisfy a different error path. No host TCP settings change.

## Code Scanning

All ten reported alerts were in test fixtures, not request-handling code:

| Alerts | Boundary change |
| --- | --- |
| 384-389: command injection | All six subprocess launch sites use a test-only helper. Canonical executable paths must equal the compiler-selected Cargo `deps` directory plus a closed crate name, 16 hexadecimal Cargo hash characters and the platform executable suffix. No shell, PATH lookup or environment-selected executable is used. |
| 380, 382, 383: source inventory paths | The scanner confines canonical paths to the repository, rejects symlinks and ambiguous paths, and checks regular files before reading. Negative fixtures cover escapes and internal/external symlinks. |
| 381: fatal fixture path | The child no longer reads a file path from an environment variable. It uses literal `fatal.log` inside a parent-owned temporary working directory. |

The helper tests reject other directories, nested/traversal paths, other crates,
malformed hashes and shell-like names. A separate Cargo target-directory run
checks that the allowlist follows the build rather than hardcoding `target/debug`.
The common crate's build script enables Cargo's compile-time `OUT_DIR`; the
helper is compiled only for tests or the existing `test-support` feature.

This is test-harness confinement, not compiler attestation or protection against
a malicious same-user process modifying the trusted build tree. No alerts are
dismissed or suppressed. GitHub's subsequent CodeQL scan determines closure.

## Validation

- Linux locked workspace tests and workspace/all-target Clippy with warnings
  denied passed.
- Common watchdog and test-executable checks passed, including a custom Cargo
  target directory. The Windows common crate and tests cross-compiled.
- Linux focused logging tests: 18 passed. All 21 real-entrypoint dump-policy
  cases passed, including failure injection with a full, undrained stderr pipe.
- Linux privacy-profile logging tests: 18 passed. Live event, fatal-listener and
  typed/legacy blocked-pipe recovery and shutdown smokes passed.
- Native Apple Silicon: common watchdog/helper tests, all 18 logging tests,
  poisoned-admin fatal test, three fatal-listener scenarios, seven event
  scenarios, and typed/legacy blocked-pipe recovery and shutdown smokes passed.

Production fatal handling, dump protection, filesystem trust, privacy policy and
audit admission are unchanged. Native Windows results are recorded below;
cross-compilation alone is not evidence of Windows pipe behavior. Stop before
Commit 05 until the independent review and GitHub gates pass.

## Native Windows Follow-up

On 2026-10-24, tested exact commit
`7a0d84eddda3a7bfccf8bbfd7d4350393d07eea3` on a fresh Windows Server 2025
x86_64 cloud host with four logical CPUs and 16 GiB RAM. The existing bootstrap
installed Rust 1.99.1/MSVC and verified the compiler inventory and ACLs. All builds
and tests ran as the non-administrator `fluxheim-build` account with
`RUSTFLAGS=-Dwarnings`, a fresh Cargo cache, and locked dependencies.

The transferred `git archive` source was checked before extraction:

```text
8ffe0ee9c97e0c5c95b6754d09474797f29f852888415e39e7f9cf9d406a9a42  fluxheim-windows-ci-7a0d84ed.tar.gz
```

Results:

- Common crate: nine tests passed, including all eight fatal watchdog subprocess
  scenarios using real OS pipes and both executable-allowlist tests.
- Observability-profile logging: 17 tests passed; poisoned-admin fatal test: one
  passed. Privacy-profile logging: 17 passed. The Unix-only FIFO case is not
  applicable to Windows and remains exercised on native Linux and macOS.
- Full locked workspace: 1,770 passing test executions, including child
  harnesses and documentation tests; zero failures or ignored tests.
- Windows release-script validation passed.
- `smoke_windows_native.ps1` passed its ACME, managed-PHP rejection, external
  TCP FastCGI, storage-lease and absolute-path prerequisites. Its live checks
  passed static HTTP, downstream and verified upstream TLS, memory/disk cache,
  proxy, load-balancer, admin, snapshot, metrics and CTRL_BREAK graceful shutdown.
  Snapshot verification reported two authenticated snapshots and none unverified.
- The remote command exited zero. No Fluxheim, Cargo or rustc processes remained
  after completion. No source changes were required for the run.

Collected transcript SHA-256:

```text
71a828161d5f67486b3684315d741c9cef4eb8c3af99eed1c25e3fd6a88e3d23  fluxheim-windows-ci-7a0d84ed-transcript.txt
```

This is native regression and loopback runtime evidence, not a release-package
qualification, public-network/ACME issuance test, or guarantee of no defects.
GitHub CI and CodeQL still need to run against the pushed fix commit; this result
does not assert that the ten hosted code-scanning alerts have closed.

## Source Scanner Follow-up: Alerts 390 And 391

The scan of `de63e87a` reported two new paths from `DirEntry::path()` to the
test inventory's `read_dir` and `read_to_string` calls. The existing canonical
root confinement and dot-dot checks used assertions, which the reported flows
did not treat as validation barriers. The other alert locations are no longer
listed as open.

The scanner now returns `PermissionDenied` explicitly for root escapes,
ambiguous paths and symlinks before enumeration or reading. Recursive and I/O
errors propagate to the top-level test, which fails rather than skipping a
directory. Direct runtime abort/exit detection and its narrow exemptions remain
unchanged. No CodeQL suppression or production change was added.

Regression fixtures exercise a valid nested Rust file, direct abort and exit
violations, an outside root, dot-dot-containing file and directory names, and
internal/external symlinks on Unix. Linux observability and native macOS logging
suites passed all 18 tests, and strict Clippy passed. Native Windows execution of
this follow-up remains pending CI because the disposable host is no longer
reachable. Hosted CodeQL must rescan the explicit guards to confirm closure.
