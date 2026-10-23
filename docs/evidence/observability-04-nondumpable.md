# Commit 04: Linux Non-Dumpable Startup

Review base: `a76078cf9c453c979829a90116129cb345631e9c`.

## Finding And Remediation

The previous launcher limits were defense in depth, not a complete answer to
Linux kernel-piped crash collectors. All three executable entrypoints now call
the common `disable_memory_dumps()` helper before any argument parsing, config
loading, crypto initialization or application threads.

On Linux the helper uses rustix's safe `PR_SET_DUMPABLE=0` wrapper, reads back
the kernel state and returns an error on syscall failure or unexpected state.
The entrypoint returns status 1 rather than continuing. This prevents the kernel
from generating a memory dump, including delivery to a piped collector, while
preserving the fatal watchdog's existing bounded termination behavior.

The already-locked rustix dependency becomes a Linux production dependency of
the common crate. No dependency versions or lockfiles change; no unsafe code,
privileged host policy changes, runtime opt-out or new background threads are
introduced. Launcher soft/hard core limits remain in place.

## Permanent Tests

- An isolated Linux child checks the actual dumpable state, repeated calls and
  inheritance by a newly spawned thread. It does not alter the parent harness.
- All eight fatal watchdog subprocess scenarios now run with the same guard.
- `scripts/smoke_linux_dump_policy.py` traces all three real executables. Normal
  startup must set and read back zero. Injected set failure, readback failure and
  unexpected readback must each fail before even `--version` can run. Nine
  additional full-stderr cases require bounded, silent failure: twenty-one
  executable cases total. Linux CI builds all binaries and runs this regression.
- Existing deployment-limit, confidential sink, privacy, saturation, listener
  exit and audit-admission regressions remain enabled.

## Original Local Validation

On 2026-10-23:

- Locked workspace: 1,838 passing executions (including child harnesses), one
  existing privileged ACME test ignored. Common standalone tests: eight passed.
- Observability/TCP-stream/UDP profile: 297 passed; privacy: 183 passed.
- All twelve real-executable syscall cases passed. Three occupied-listener
  smokes, seven operational event scenarios and four backpressure scenarios passed.
- Systemd socket activation/readiness smoke passed. A real transient user
  service launched the hardened executable with the packaged syscall filter and
  `NoNewPrivileges`. Both packaged core-limit settings still produced `(0, 0)`.
- Built a fresh `fluxheim:non-dumpable-smoke` image through the repository's
  Containerfile with `profile-observability`. Container startup, config validation,
  runtime UID, live HTTP and running-process zero core limits passed with default
  Podman security policy. This is a new 1.9.0 binary, not the older released image.
- An earlier ad-hoc attempt to mount a host-built debug binary into older runtime
  images exited with signal 11; it is not used as release evidence. The supported
  builder/runtime pair above passed. No change to the supported build recipe was
  needed or made to obtain that result.
- Workspace/all-target Clippy with warnings denied, formatting, dependency audit,
  cargo-deny, deployment/refresh policy regressions and documentation checks passed.
- Windows common-crate and test cross-compilation passed. Native Windows/macOS
  execution remains a GitHub gate; no claim of native tests is made here.

## Follow-up: Silent Security-Control Failure

Review base: `b9f774d1`. The error diagnostic itself could block on a full stderr
pipe before reaching `exit(1)`, while the process could still be dumpable. All
three entrypoints now exit silently on guard failure. The guard, readback and
runtime fatal diagnostics are unchanged; no watchdog or abort is introduced into
the potentially dumpable startup failure path.

The regression fills a real pipe until even a one-byte nonblocking write fails,
restores blocking mode and attaches its writer as the child's actual stderr.
It injects each of the three `prctl` failure outcomes into each executable.
The parent never drains stderr while the child is running. A five-second timeout
fails the test and kills/reaps the tracer and tracee process group; successful
termination must have status 1, no stdout, and the original pipe contents intact.
Normal captured-stderr cases also require no diagnostic output.

Red/green validation reproduced the old hang against the unmodified server
entrypoint, then passed all twenty-one cases after removing the output. The
existing Linux CI smoke automatically includes these new cases.

Follow-up validation passed: full locked workspace (1,838 passing executions,
one existing privileged ACME test ignored), eight common tests including the
eight-scenario watchdog regression, three fatal-listener cases, seven operational
event cases, four backpressure scenarios, workspace/all-target Clippy with
warnings denied, formatting and documentation checks. No dependencies or
platform policies changed. Native Windows/macOS execution remains for GitHub CI.

## Boundaries

The Linux flag is not an anti-root or compromised-process boundary. It restricts
ordinary debugger attachment and some `/proc` access. Exec/credential changes
can reset it; Fluxheim entrypoints reapply it, but external children such as
PHP-FPM need separate policy. Library embedders must establish the guard before
loading secrets themselves. Windows/macOS remain operator-managed rather than
silently claiming an equivalent Linux control.

The [security guidance](../../SECURITY.md#fatal-termination-and-memory-dumps)
documents these limits and retained host defense-in-depth controls. No host
collector configuration was changed. Independent retest and green GitHub checks
are required before Commit 05.
