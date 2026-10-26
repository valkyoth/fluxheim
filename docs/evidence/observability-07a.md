# Commit 07A: Dedicated Windows QEMU Workflow

Status: local qualification complete, including baseline restore and fresh
native rebuild. Owner confirmed clean pentest, green GitHub and resolved
code-scanning alerts through `2c383562`, and authorized Commit 08. Accepted for
progression, not release acceptance.
Date: 2026-10-25. Application source under test:
`792b0fdc1805cd7a2ec66350877e72e30a789bd7`.

## Scope

The [dedicated VM guide](../guides/windows-qemu.md) describes the project-local
launcher, offline baselines, SSH bootstrap, host forwarding and resource limits.
No production Rust, Cargo manifest or lockfile changes are part of this work.
VM media/state, credentials, machine identity and detailed infrastructure logs
remain Git-ignored. Another project's VM and backup were not changed.

The owner installed and activated Windows 11 Pro from supplied media. Native
execution uses QEMU 11.1.2 with KVM and host CPU passthrough. Secure Boot and TPM
were confirmed enabled/ready; VBS was not running. No test-signing or security
requirement bypass was introduced. This is Windows 11 evidence, not additional
Windows Server qualification or a claim of independently measured installation
media.

The working guest uses eight vCPUs and 16 GiB RAM. The host service caps aggregate
CPU time at six logical CPUs and sets 18/20 GiB memory high/maximum thresholds.
By default, the virtual disk is limited to 64 MiB/s. Offline snapshot operations pace their
application I/O to 32 MiB/s and use background CPU/I/O priorities. These controls
were introduced after a full-image restore competed with a large owner-initiated
USB transfer; the restore was interrupted before the directory swap. The owner
confirmed the desktop remained responsive during the subsequent limited build.
After qualification and completion of the owner's transfer, the owner authorized
unthrottled disk I/O for the restore/rebuild. The running guest's disk limit was
removed through identity-checked QMP; CPU/RAM limits were unchanged. Explicit
per-run `--unthrottled-io` flags now support this without weakening the defaults
or skipping checkpoint checksums. After normal guest shutdown, the full restore
completed: baseline and copied-state checksums passed, the previous working
state was retained separately, and only the restored working settings were
changed back to eight vCPUs/16 GiB. The restored guest booted with the original
SSH identity and passed compiler hash/ACL checks. A fresh native rebuild and
live smoke then passed without reusing the previous Cargo cache or target tree.

## Provisioning

Pinned Rust 1.99.1, Visual Studio 2022 Build Tools, PowerShell, Git, Python and
CMake were installed through the existing provisioning workflow. Builds run as
the dedicated non-administrator account. The existing compiler inventory/ACL
checks (`run_windows_release_builder.ps1 -ValidateBuilderOnly`) passed and
administrator SSH was rejected. No trusted-toolchain or source-signature gate
was disabled.

The first preparation exposed an OpenSSH distribution mismatch: WinGet OpenSSH
was already installed, but preparation attempted the Windows optional component.
The service needed console recovery with the matching, checksum-verified MSI.
Its original SSH host key was preserved. Preparation now resolves the registered
service executable from an allowlist of standard installation paths, validates
configuration with that binary and never installs a second distribution. Missing
services, unsupported executable paths and extra service arguments fail before
authentication-policy changes. The updated PowerShell validator passed on both
Linux and the actual Windows guest.

Native non-admin testing also exposed two logging-fixture assumptions that
administrator CI had not caught. The helper now sets `RemoteSigned` only for
its Windows PowerShell child process, rather than depending on machine policy.
It applies only the DACL through `DirectoryInfo.SetAccessControl`, avoiding
Windows PowerShell `Set-Acl`'s attempt to persist audit permissions. The protected
ACL and all three inherited access rules are still read back and checked. No
audit privilege or administrator membership was granted to the build account.

The real-PHP fixture's pinned download had moved to PHP's official archive.
Its URL now uses that archive, with the existing version and SHA-256 unchanged.
A failed-download retest also verified that cleanup diagnostics no longer mask
the original exception. The full HTTP/HTTPS PHP test then passed after download
and checksum verification. This is an external test interpreter, not PHP bundled
in the Windows release archives.

## Local Results

- Host-only launcher/checkpoint tests: 23 passed, including throttling and
  opt-in unthrottled copies, identity, resource/port/lock conflicts, corruption,
  interrupted copies and retention.
- Release-helper tests: 21 passed, including consistent SSH/SCP ports,
  separate host-forwarded versus guest-listening HTTP/HTTPS ports, and the
  checksum-pinned PHP fixture's non-masking diagnostics.
- Documentation-layout tests: four passed; links and diff checks passed.
- Full native `cargo test --workspace --locked`: passed.
- Native observability/PHP profile library suite: 268 passed.
- Logging-fixture regressions: ten passed on Linux and native Windows, including
  actual non-admin ACL creation/readback and cleanup.
- Live native log rotation: passed for rename, deletion, truncation, unsafe
  replacement rejection, recovery, concurrent reload and status reporting.
- Linux live log rotation and confidentiality regressions: passed with the
  same fixture source; the Windows-only changes leave that path unchanged.
- Request-correlation command tests (nine) and native telemetry tests (ten):
  passed. The live HTTP/1.1/TLS HTTP/2, FastCGI, WebSocket, retries, resets,
  JSON/OTLP and operational-metric assertions also passed. The Python fixture
  printed connection-reset diagnostics during cancellation; all assertions
  and the harness exit status passed.
- Native `scripts/smoke_windows_native.ps1`: passed, covering static serving,
  downstream/verified upstream TLS, memory/disk cache and persistence across
  restart, proxy, load balancer, admin, snapshots, metrics and graceful shutdown.
  Its ACME-enabled, managed-PHP rejection and external FastCGI regressions passed.
- All seven optimized Windows profiles built as ZIP and tar.gz archives.
  ZIP extraction and every packaged executable's version check passed.
  The archived Wasm policy executed its real allow/deny smoke successfully.
- All 14 downloaded archives matched the guest-generated SHA-256 manifest;
  host ZIP integrity checks and tar.gz listing checks passed.
- Host-originated HTTP/HTTPS tests through QEMU forwarding passed for the
  packaged proxy, load-balancer, cache and full profiles, including strict host
  routing, failover and persistent disk-cache hits with the origin stopped.
- Packaged PHP profile with a real external PHP CGI process: HTTP and verified
  HTTPS GET/POST checks passed from the Linux host. These are forwarded local
  tests, not Internet reachability or public ACME issuance.
- Two powered-off baselines were copied, checksum-verified and made read-only:
  clean installed Windows and tool-equipped Windows. Neither is booted writable.
- Tool-equipped baseline restore and fresh native rebuild: passed. The restored
  guest repeated the full native live smoke, all 11 Windows security helper
  tests and all 17 Windows filesystem-trust tests. Its executable reports
  `fluxheim 1.9.0 (qemu-restored-g792b0fdc)`. No build or test server processes
  remained after completion. The seven-profile package matrix above was run
  before restoration; it was not repeated as part of this recovery exercise.

Application sources were transferred as a local Git archive of the exact commit;
only the currently reviewed provisioning/helper and smoke-fixture scripts were
overlaid for validation. Development binaries are marked `qemu-qualification-g792b0fdc`.
This is not a signed-tag release, reproducibility result or publication approval.

## Remaining Gates

The restore/rebuild gate is complete. The earlier interrupted staging copy is
retained but was not reused for the successful restoration. Previous working
state and all downloaded package evidence remain retained separately.
Final release-candidate archive qualification remains Commit 11.
Stop for pentest, exact-commit GitHub/CodeQL and user approval before Commit 08.

## Local Builder Security Follow-Up

The additional tooling review identified guest-escape blast radius, online
guest networking and single-builder artifact evidence as high-assurance gaps.
These were reviewed separately from the clean webserver-source assessment.

The launcher now requires the system QEMU/swtpm paths, enables QEMU's seccomp
policy (obsolete calls, privilege elevation, spawning and resource control
denied), and disables implicit devices and configuration loading. It does not
fall back to an unsandboxed launch. This is targeted defense in depth, not a
dedicated host identity or filesystem confinement. Outbound networking remains
enabled and no independent artifact-build requirement was added. The
[security boundary](../guides/windows-qemu.md#security-boundary) documents these
remaining risks explicitly, including what checksums and repeat builds cannot
prove. The three recommendations are not reported as fully remediated.

After owner-performed normal shutdown, the existing Windows guest booted with
the new flags and its original identity. Host kernel inspection confirmed
`NoNewPrivs: 1`, `Seccomp: 2` and an installed seccomp filter on QEMU. Strict SSH
and the compiler inventory/ACL check passed. The full native live smoke and
all 11 Windows security helper plus 17 filesystem-trust tests passed again.
This reused the earlier development build/cache; it was not a new release or
repeat of the seven-profile archive matrix. Baselines were not modified.

Host launcher/checkpoint regressions now total 25 passing tests, including the
mandatory sandbox/device arguments and rejection of missing system executables
without PATH fallback. All 21 release-helper tests, four documentation-layout
tests, PowerShell release-policy validation, doc links and diff checks passed.

### PATH Helper Follow-Up (FH-WIN-001)

The subsequent review identified remaining PATH-selected `ionice`, `qemu-img`
and `remote-viewer` calls. All now use fixed `/usr/bin` paths. The launcher
validates all five tools before applying background priority; the shared
priority helper independently validates `ionice` before execution, covering
offline checkpoint/restore commands without adding a KVM requirement.

All 30 launcher/checkpoint tests passed. Regressions cover missing and
non-executable system tools, validation before any launch, the offline priority
helper's fail-closed behavior, and exact child executable paths with an untrusted
PATH. This follow-up does not change the guest configuration, seccomp policy,
networking, resource limits or release-provenance boundaries. It does not require
modifying the running guest or saved baselines.

The low-severity shutdown availability follow-up is also addressed: `shutdown`
dispatches directly to the existing identity-checked QMP operation before tool
validation or background-priority setup. Init/start still require the complete
toolchain. All 31 launcher/checkpoint tests passed, including a regression that
rejects any external helper execution during shutdown and the existing name/UUID
mismatch tests. No actual guest shutdown or baseline modification was needed.

### CodeQL Checkpoint Paths (#400-#424)

All 25 open Python alerts on `62eb5068` followed the CLI checkpoint name through
the checkpoint/verify/restore filesystem operations. The existing filename
allowlist remains; a shared resolver now also checks the canonical path against
the baseline directory with a directory-separator boundary and rejects linked
roots and leaf aliases before operations or priority-helper execution.

Local CodeQL 2.27.3 with `codeql/python-queries` 1.8.13 reproduced all 25
`py/path-injection` results on the two original VM modules and zero on the
updated modules. The run enabled the local threat model in addition to the
default remote model, matching GitHub's `remote_and_local` setting. The default
remote-only run returned zero even before the fix and was not used as evidence
of remediation. No query exclusions, suppression comments or alert dismissals
were added. GitHub must still analyze the new commit to close its alerts.
The complete Python code-scanning suite also returned zero findings on these
two modules under the same remote-and-local threat model.

All 37 launcher/checkpoint tests passed, including traversal/absolute-path/name
rejection, sibling-prefix and internal/dangling/self symlinks, validation before
CLI side effects, and a synthetic CLI checkpoint/verify/restore roundtrip.
Release-helper tests (21), log-fixture tests (10), documentation-layout tests (4),
PowerShell release-policy validation and diff checks also passed. No live VM,
saved baseline, Rust code or dependency was changed.
