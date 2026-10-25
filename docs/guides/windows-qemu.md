# Dedicated Windows QEMU VM

Status: Commit 07A local qualification complete; pentest and exact-commit CI
pending. Installation and baseline creation alone are not evidence that Windows
tests or release packaging have passed. The existing cloud builder remains supported.
See the [qualification record](../evidence/observability-07a.md) for completed
native checks and the remaining gates.

## Host And Guest

Use an x86_64 Linux host with KVM, `qemu-system-x86_64`, `qemu-img`, `swtpm`
and `remote-viewer`, plus `ionice` from util-linux. The launcher requires KVM and never falls back to software
CPU emulation. Install official Windows 11 x64 media with your own appropriate
license. No media, activation keys or activated image is distributed here.

Defaults are 8 vCPUs, 16 GiB RAM and a sparse 192 GiB disk. Creation requires
disk capacity plus 32 GiB free on the host. Boot requires 32 GiB free and leaves
at least 8 GiB of available host RAM. Sparse images grow; these startup checks
do not guarantee sufficient space throughout later builds or backups. Monitor
host capacity before large builds and copying baselines.

Launcher and checkpoint processes use nice +10 and idle-class I/O priority;
children inherit these settings. The guest disk has a combined read/write
limit of 64 MiB/s. Snapshot copy and hashing loops pace their combined
application-level I/O to 32 MiB/s in 1 MiB chunks. Kernel writeback and storage
scheduler behavior still vary; these are not guarantees of desktop latency or
device-wide bandwidth. Avoid snapshot operations during large host transfers.
Keep guest Cargo jobs modest (for example, six). Host CPU passthrough does not
give the guest every host CPU or all host RAM.

Full checkpoints/restores copy and reread the complete image several times.
At the default I/O limit, restoring a 44 GiB image takes roughly two hours even
before storage overhead. Phase messages distinguish copying from verification;
neither task runs a guest during that work. Schedule these operations separately
from interactive builds and other large transfers.

When the host disk is otherwise idle, explicitly disable bandwidth pacing for
one operation with `--unthrottled-io`:

```sh
# Requires normal guest shutdown first; retains the previous working state.
python3 scripts/windows_qemu_state.py restore tools-installed --confirm-restore --unthrottled-io
# For the next boot (also accepted when starting through systemd):
python3 scripts/windows_qemu.py start --unthrottled-io
```

This does not change CPU/RAM allocation, background priorities, integrity
verification or saved baselines. Defaults remain throttled on later invocations
without the flag. Boot flags do not change an already running guest. Unthrottled
copies can compete with desktop I/O again; completion time depends on storage.

Change `settings.json` only while the VM is off. Existing VM settings and saved
baselines retain their original CPU/RAM values; changing launcher defaults does
not rewrite them. After restoring an older baseline, review the working copy's
settings before booting. Never edit the read-only baseline to change resources.

The guest sees the host CPU model through KVM, not an exclusively assigned set
of physical cores. Do not add `target-cpu=native` or native C optimization flags
to release builds: published executables must remain portable.

## Prepare Once

Use a matched, Microsoft-key-enrolled Secure Boot/SMM firmware code and variable
template from your Linux distribution. For openSUSE's raw firmware pair:

```sh
python3 scripts/windows_qemu.py init \
  --firmware-code /usr/share/qemu/ovmf-x86_64-smm-ms-code.bin \
  --firmware-vars /usr/share/qemu/ovmf-x86_64-smm-ms-vars.bin
```

Optional creation flags are `--cpus`, `--memory-gib` and `--disk-gib`. The launcher
creates only `release-reports/windows11-fluxheim-vm` under this checkout. It
refuses to initialize an existing directory, even if preparation was interrupted.
Inspect incomplete state manually; there is no automatic delete or repair.

This private, Git-ignored directory holds a new UUID, system/baseboard/chassis/
disk serials, locally administered MAC, disk, firmware copies and TPM state.
Generic virtual-machine identifiers are not reused. Keep these files together;
do not regenerate identity on subsequent boots or borrow another project's
firmware variables/TPM. If Windows setup unexpectedly names an organization,
stop and investigate the media and device enrollment; do not enter credentials.

The template enables Secure Boot capability and supplies enrolled keys. Confirm
the actual guest Secure Boot, TPM and VBS state after installation. Do not use
development test-signing or disable security requirements to make tests pass.

## Install And Boot

```sh
python3 scripts/windows_qemu.py start --iso /absolute/path/Windows11.iso
```

The installer is interactive. Finish installation, activation and updates in
the viewer. Select the Windows edition matching your license. This launcher
does not bypass setup requirements, accept license agreements or enter keys.
NVMe storage and an emulated Ethernet adapter avoid needing a separate VirtIO
driver during installation. Clipboard sharing, host-folder mounts and agent
file transfer are disabled.

Keep the launcher running. Closing the viewer does not shut down Windows;
reopen the console with the `remote-viewer` command it prints. The console URI
is also recorded privately in `console-uri.txt`. QEMU and TPM diagnostics are
in `qemu.log` and `tpm.log` in the state directory. Shut down normally from the
Windows Start menu and let the launcher exit. Do not terminate QEMU or swtpm
while Windows is writing its disk.

`python3 scripts/windows_qemu.py shutdown` requests normal ACPI shutdown after
checking the running VM's name and UUID. Windows can ignore that request or wait
for an interactive confirmation. Wait for the launcher to exit; otherwise use
the guest console to shut down. The build account intentionally has no shutdown
privilege. Checkpoints refuse to copy a VM that is still running.
Shutdown uses Python's QMP connection directly, without invoking external tools
or the priority helper. Missing build/viewer utilities cannot block that request;
VM name and UUID checks still apply.

Later boots omit `--iso`:

```sh
python3 scripts/windows_qemu.py start
```

For a desktop host using systemd, a user service can additionally cap the entire
VM process group. From the repository root, with the default 16 GiB guest:

```sh
systemd-run --user --unit=fluxheim-windows-vm --collect \
  --property=Type=exec --property=CPUQuota=600% \
  --property=MemoryHigh=18G --property=MemoryMax=20G \
  --property=WorkingDirectory="$PWD" \
  --setenv=DISPLAY --setenv=WAYLAND_DISPLAY --setenv=XAUTHORITY \
  /usr/bin/python3 "$PWD/scripts/windows_qemu.py" start
```

The CPU quota is six logical CPUs' worth of aggregate runtime, not 600 percent
of the whole machine. The guest still sees eight vCPUs. The memory thresholds
include QEMU overhead; never set them equal to guest RAM. `MemoryMax` is a
last-resort OOM guard and can kill the VM if exceeded, not a graceful shutdown
mechanism. Monitor usage and shut Windows down normally before changing memory
allocation. Do not use `systemctl stop` as the normal guest shutdown operation.

An exclusive lock prevents a second launch. Never delete a lock to bypass it.
The fixed forwards bind only to Linux loopback:

| Host port | Guest port | Purpose |
| --- | --- | --- |
| 2223 | 22 | SSH after provisioning |
| 13390 | 3389 | RDP if enabled explicitly |
| 18080 | 80 | HTTP live tests |
| 18443 | 443 | HTTPS live tests |

QEMU forwarding alone does not install SSH, enable RDP or change Windows
Firewall. Verify the new SSH host key from the guest console before trusting
it. No LAN listeners or host firewall changes are made. Windows has outbound
NAT network access for setup and updates; this is not an isolated malware lab.

## Security Boundary

This is a single-owner development/build VM, not a hostile-code analysis service
or an independently verified release system. Cargo build scripts and procedural
macros execute code: a fresh guest and read-only compiler reduce persistence
opportunities but do not make malicious dependencies safe.

The launcher uses fixed `/usr/bin` paths for `qemu-system-x86_64`, `swtpm`,
`qemu-img`, `remote-viewer` and `ionice`, not PATH-selected copies. It checks
these executables before starting any helper. Offline checkpoint operations
check their sole external helper, `/usr/bin/ionice`, before running it; they
do not require KVM. QEMU always starts with `-no-user-config`, `-nodefaults`
and `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`.
Required display, storage, network and input devices remain explicitly declared.
If the installed QEMU cannot apply this policy, startup fails; there is no
automatic unsandboxed fallback. Keep QEMU, swtpm, firmware and the host kernel
updated through trusted distribution packages. Fixed executable paths are not
version pins or cryptographic package verification.

Seccomp reduces available system calls; it does **not** confine QEMU's filesystem
access to this VM. QEMU and swtpm still run as the invoking Linux user. A successful
escape could expose that user's files and credentials. The resource-limited user
service is not a separate security identity or filesystem sandbox. Do not use
this launcher for intentionally hostile guest workloads; use a separately managed
host or a confined VM service for that threat model. Do not copy release-signing
private keys into Windows or forward signing/SSH agents to it.

Outbound networking remains enabled for Windows updates, tool installation,
source/dependency fetching and online tests. Loopback-only incoming forwards do
**not** block guest access to host services, reachable LAN services or the Internet.
Do not rely on them as an egress firewall. An offline workflow would require
QEMU `restrict=on`, preloaded dependencies and offline build commands; it is not
implemented or claimed by this workflow. No host firewall changes are automated.

Release checksums detect transfer corruption or later modification relative to
the supplied manifest, not a malicious builder that replaces both. Two builds on
this VM check repeatability, not independent provenance. Signed tags authenticate
source selection, not resulting executables. Independent builds across separately
administered hosts are a stronger optional release policy, not a requirement of
the current Linux ARM/Windows release model. Treat host/guest compromise as loss
of trust: discard affected outputs, investigate and rebuild on a clean trusted
host rather than accepting its checksum report.

These are explicit residual risks, not claims that all three high-assurance
pentest recommendations have been implemented. See
[QEMU security guidance](https://www.qemu.org/docs/master/system/security.html).

## Baselines And Provisioning

Before provisioning tools, shut down and preserve a clean installed baseline
including disk, firmware code/variables, TPM and identity, with integrity hashes.
Store recovery material privately. Then reuse the
[Windows builder provisioning](windows-release-builders.md), and preserve a
second powered-off tool-equipped baseline. Never boot a baseline writable.

```sh
# Windows must have shut down normally; the launcher must have exited.
python3 scripts/windows_qemu_state.py checkpoint clean-installed
python3 scripts/windows_qemu_state.py verify clean-installed
```

Checkpoints are copied to a separate Git-ignored directory, checksum-verified
and made read-only before becoming named baselines. Names are never overwritten.
Disk, TPM, firmware and identity are saved together. Failed copies retain an
`.incomplete-` directory for inspection. Do not treat that as a valid baseline.
Hashes detect accidental changes, not a malicious host administrator; the owner
and host are trusted. Store a separate backup outside this physical disk too.

Checkpoint names are single ASCII components (1-64 characters: first a letter
or digit, then letters, digits, underscores or hyphens). All three checkpoint
commands resolve the selected path and enforce a baseline-directory boundary
before use. Linked baseline roots and linked checkpoint names are rejected,
including links to another checkpoint in the same directory. This does not
provide isolation against a malicious process running as the host owner.

After initial administrator SSH access and host-key verification, provision:

```sh
FLUXHEIM_WINDOWS_ADMIN_USER=fluxheim \
FLUXHEIM_WINDOWS_SSH_PORT=2223 \
bash scripts/bootstrap_windows_release_builder.sh \
  127.0.0.1 "$HOME/.ssh/id_ed25519_windows_fluxheim" 10.0.2.2/32
```

The bootstrap uses the public part of that key for the separate `fluxheim-build`
account, installs administrator-controlled tools, then restricts SSH to the
build account. The administrator remains available through console/RDP, not
SSH. The CIDR here is QEMU's guest-visible gateway, not a public host address.
The SSH port defaults to 22 and administrator defaults to `Administrator` for
cloud hosts. The staging path is `C:\Users\ADMIN_USER\FluxheimBootstrap`; the
administrator profile must exist at that path. An existing staging directory
is never adopted or overwritten. Git's configured SSH signing public key and
email supply the trusted release-tag signer policy.

Install and start OpenSSH before bootstrap. Both the Windows optional component
and Microsoft's separately installed OpenSSH package are supported at their
standard Windows/Program Files paths. Preparation reads the registered `sshd`
service executable and uses that same binary for configuration validation. It
does not install another OpenSSH distribution. A missing service, unsupported
path or service command with extra arguments stops preparation before changing
authentication policy. Repair SSH from console/RDP first, preserving the host
keys and `C:\ProgramData\ssh` configuration. Verify the host fingerprint again
before reconnecting. Do not bypass host-key checking to recover connectivity.

Save the second baseline after provisioning and normal shutdown:

```sh
python3 scripts/windows_qemu_state.py checkpoint tools-installed
```

Restore is explicit, refuses a running VM, verifies checksums before swapping
state, and retains the previous working state and logs in a uniquely named
directory. It never boots the baseline itself:

```sh
python3 scripts/windows_qemu_state.py restore tools-installed --confirm-restore
# Review the restored working settings before booting; keep the baseline unchanged.
python3 scripts/windows_qemu.py start
```

Copies and retained working states need additional space. Review and export
evidence before manually removing old retained states. An old tool baseline is
for development only: official packaging still enforces the existing 24-hour
provisioning age limit. Use the clean baseline and fresh provisioning for an
official release; never rewrite a provisioning timestamp to bypass the policy.

Set `FLUXHEIM_WINDOWS_X64_HOST=127.0.0.1`, `FLUXHEIM_WINDOWS_SSH_PORT=2223` and
`FLUXHEIM_WINDOWS_SSH_KEY` when running `scripts/release_helper.sh`. All Windows
preflight, upload, execution and download operations use that same port and
strict host-key verification. Linux ARM and macOS sections are unchanged.

For packaged-profile tests from the Linux host, the existing
`scripts/smoke_windows_public_profiles.sh` also accepts:

```sh
export FLUXHEIM_WINDOWS_SSH_PORT=2223
export FLUXHEIM_WINDOWS_PUBLIC_HTTP_PORT=18080
export FLUXHEIM_WINDOWS_PUBLIC_HTTPS_PORT=18443
export FLUXHEIM_WINDOWS_LISTEN_HTTP_PORT=80
export FLUXHEIM_WINDOWS_LISTEN_HTTPS_PORT=443
```

Use `127.0.0.1` as host/public address and a local fixture name such as
`fluxheim-qemu.test`; the harness supplies its own test CA and `curl --resolve`.
Permit TCP 80/443 from 10.0.2.2 in Windows Firewall first. This is a real
host-to-guest HTTP/HTTPS test, not public Internet reachability or ACME issuance.
Without these variables, the existing cloud port defaults are unchanged.

Native workspace/live tests and all seven archive profiles remain acceptance gates.
A reused development VM is not automatically an official release builder.
Repeated builds on one physical host do not establish independent trust-domain
verification. Same-disk snapshots cannot protect against loss of the host disk.

Host-only launcher regressions:

```sh
python3 scripts/test_windows_qemu.py
python3 scripts/test_windows_qemu_state.py
scripts/validate_release_helpers.sh
```

References: [QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html)
and [Windows requirements](https://www.microsoft.com/en-us/windows/windows-11-specifications).
