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
audit admission are unchanged. Native Windows execution remains pending CI;
cross-compilation is not evidence of Windows pipe behavior. Stop before Commit 05
until the independent review and GitHub gates pass.
