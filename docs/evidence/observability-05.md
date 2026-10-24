# Commit 05: Protected File Lifecycle

Date: 2026-10-24. Review base: `ee98efea`. Unreleased 1.9.0; implementation
is ready for incremental pentest and exact-commit CI, not release acceptance.

## Scope

All four existing logging workers share one protected file handle and serialize
whole records with rotation. Worker-triggered checks are limited to once per
second, including failed attempts. Failed reopen keeps the old handle; write
failure latches the sink until restart. No producer performs file I/O or acquires
the file mutex. No extra thread, unbounded queue, retry or spool was introduced.
The authenticated status response adds bounded counters and flags, not paths or
raw error details. stdout/stderr and fatal watchdog behavior remain unchanged.

The [operator guide](../guides/logging.md) specifies append/truncate semantics,
ordering, failure/loss behavior, external retention responsibilities and trust
boundaries. The existing accepted non-durable audit limitation remains.

## Verification

- Linux: locked workspace tests, logging/runtime unit tests and strict workspace
  Clippy. New cases exercise rename/delete/truncate, retained-handle fallback,
  rate limiting, crash aliases, concurrent lane writes/rotation, short writes,
  write failures, hostile symlinks/FIFOs, permission loss and bounded shutdown.
- Linux live binary: rotation smoke, operational-event scenarios, bounded
  backpressure/recovery/shutdown, fatal listener failures and non-dumpable startup
  including full-stderr fault injection. Snapshot reload concurrent with
  rotation and HTTP requests preserves audit delivery and service. One fatal-listener run timed out during
  overlapping workspace/build/smoke runs; rebuilding the required stream/UDP
  profile and rerunning without competing builds passed.
- Linux Podman: real 1 MiB tmpfs filled to ENOSPC while Fluxheim ran in a
  disposable Tumbleweed container. Asserted responsive HTTP, terminal sink-error
  status, no replay after freeing space and no stderr fallback.
- Native Apple Silicon macOS: 26 logging tests and live rename/delete/truncate,
  rejected replacement, recovery, concurrent snapshot reload and authenticated-status smoke passed.
- Windows x86_64 MSVC cross-check of the observability library passed with
  cargo-xwin, including compilation of its tests. Native Windows sharing-conflict
  tests and live rotation/pending-deletion smoke are
  required in CI; this session did not have a native Windows host. A compile
  result is not proof of Windows filesystem behavior.
- Privacy-profile library suite: 191 passed. Documentation layout, links,
  development/release metadata and Windows release-script validators passed.
  Cargo audit reported no advisories across the 449 locked dependencies.

No dependency versions or runtime feature defaults changed. GitHub runs the
rotation smoke on Linux, Apple Silicon macOS and Windows. Native evidence above
is scoped to these commands, not all archives or the final release candidate.

## Confidentiality Retest Remediation

Review base: `11d41ffe`. The pentest identified that the integrity-only file
check accepted logs readable by other users. Both open/reopen and the per-record
handle check now use the existing confidential-file policy. Unix 0640/0644 and
Windows ACLs granting untrusted readers are rejected; existing permissions are
never silently repaired. Startup rejection precedes truncation. A readable
replacement leaves the private old handle in service. Active confidentiality
loss latches the shared sink before another record is written; restoring
permissions does not clear that latch.

Three new regression tests failed on the vulnerable implementation before the
fix. They cover group/everyone read access, append and truncate startup modes,
reopen fallback and recovery, and active permission loss both before and after
the reopen deadline. The active failure is shared across lane clones. Unix
uses 0640 and 0644; Windows uses explicit protected ACLs for Guests and Everyone.
Windows-only test code reuses already-locked `windows-permissions` 0.2.4 as a
dev dependency; no package versions or production dependency set changed.

Linux runtime tests (51) and native Apple Silicon runtime tests (49) passed.
The expanded live smoke passed on both: a 0644 replacement remains unchanged,
repair to 0600 permits reopening, and active 0640 permissions prevent further
records while HTTP remains responsive. Locked workspace tests, privacy tests,
strict workspace Clippy and Windows MSVC test cross-compilation also passed.
Existing operational-event, backpressure, fatal-listener and Linux non-dumpable
startup smokes passed, as did the real container ENOSPC scenario. Privacy-profile
tests passed 194 cases; no assertions were relaxed to accommodate the fix.
Native Windows execution remains a required CI check, not a local pass claim.

## Native Windows CI Follow-Up

The [f39a26ad Windows run](https://github.com/valkyoth/fluxheim/actions/runs/40090056662/job/120860730363)
passed the full workspace tests, including all three new confidentiality tests
with Guests/Everyone ACLs, file lifecycle and sharing-conflict tests. Native
runtime parity also passed. The new live rotation smoke then failed before
server startup: its generated config was rejected for an untrusted filesystem
component. This is not a failure of the confidentiality assertions.

The Python smoke now protects its empty Windows fixture directory with an
explicit inheritable DACL before creating config, token or key files. Only the
current user, SYSTEM and Administrators receive full control. The helper reads
the ACL back and checks protection, identities, rights and inheritance; a setup
failure prevents server launch. It does not modify production ACL policy or
relax any permission assertion. The fixture regression suite checks argument
handling, setup ordering, error propagation and cleanup. On Windows it also
executes the ACL helper; the live smoke remains required before accepting this
follow-up. No Rust source, manifest or lockfile changes accompany this fix.

The [2ab8d92f run](https://github.com/valkyoth/fluxheim/actions/runs/40091527815)
passed Linux and macOS. Windows passed the protected-fixture tests and advanced
through the live rotation smoke to deletion. That assertion incorrectly
required a pending-delete reopen error; it did not allow successful recreation,
although the Rust lifecycle tests already account for both outcomes. The smoke
now requires exactly one successful reopen or exactly one retained-handle
reopen error, no write failure, and an additional written ordinary record.
Recreation must produce a fresh log containing the expected record; a pending
delete must complete after process exit. A no-op still times out, and cleanup
no longer masks an earlier assertion failure.

CodeQL alerts 392, 395 and 396 traced to the arbitrary `--quota-dir` input. That
option is removed, not suppressed: `--quota` opts into the fixed `/quota` mount
only, on Linux. The mount must not be a symlink, must be an actual empty mount,
and must have a positive capacity of at most 8 MiB before fixture creation.
These checks raise errors even with Python assertions disabled. Regression
tests reject arbitrary path arguments, invalid mounts, existing data and
oversized/zero-capacity mounts, and cover both deletion outcomes and failures.
Native Windows execution and CodeQL rescanning must confirm this follow-up;
local tests are not evidence that GitHub has closed the alerts.
Local verification passed nine fixture/deletion/quota regressions, the Linux
live rotation/confidentiality smoke and the disposable 1 MiB container ENOSPC
test using the fixed mount. Documentation and Windows script-policy validators
passed. The macOS builder was unreachable for this follow-up; its prior green
run is not relabelled as verification of these script changes.

After the builder returned online, the scripts from `14d5433c` were transferred
to the existing Apple Silicon qualification workspace and rerun. All nine
fixture/deletion/quota regression tests and the live rotation smoke passed,
including deletion/recreation, confidentiality rejection, repaired-replacement
recovery and concurrent snapshot reload. This reused the previously tested
native binary: the follow-up changed scripts/docs only, not Rust or build
inputs. Windows execution and CodeQL rescanning remain separate GitHub gates.

## Repeatable Commands

```sh
cargo test --locked --workspace
cargo test --locked -p fluxheim --lib --no-default-features --features profile-observability runtime::
cargo test --locked -p fluxheim --lib --no-default-features --features profile-privacy
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --no-default-features --features profile-observability,stream-proxy,udp-proxy --bins
python3 scripts/smoke_log_file_rotation.py --binary target/debug/fluxheim
python3 scripts/smoke_operational_events.py --binary target/debug/fluxheim
python3 scripts/smoke_operational_backpressure.py --binary target/debug/fluxheim
python3 scripts/smoke_fatal_listener_failures.py --binary target/debug/fluxheim
python3 scripts/smoke_linux_dump_policy.py --bin-dir target/debug
```

For native macOS use the logging unit filter and rotation smoke above. Run the
Windows smoke with `target/debug/fluxheim.exe` after the full-profile native build.
Do not run builds with different profiles concurrently against the same output
binary while smoke tests consume it.

For the additional destructive disk-full case, use a disposable tiny mount only:

```sh
podman run --rm --network host --security-opt label=disable \
  --tmpfs /quota:rw,size=1m,mode=0700 \
  -v "$PWD:/workspace:ro" -w /workspace \
  registry.opensuse.org/opensuse/tumbleweed:latest \
  sh -c 'zypper --non-interactive install --no-recommends python3 && python3 scripts/smoke_log_file_rotation.py --binary target/debug/fluxheim --quota'
```

This is a disposable test harness, not a release-image recipe: the container
installs Python, mounts source/binary read-only and binds listeners to loopback.
The explicit `--quota` mode only accepts the empty Linux `/quota` mount and
refuses capacities larger than 8 MiB; never mount a production volume there.
Native Windows/macOS disk quotas, stalled kernel I/O and
external log-collector integration remain broader platform qualification work.
