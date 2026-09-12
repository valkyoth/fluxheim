# Windows Release Builders

Fluxheim `1.8.2` uses a native Windows x86_64 host for its unsigned portable
archive evidence. A Linux cross-build is not accepted as a substitute for the
native Windows ACL, locking, shutdown, and live-runtime checks.

This is release infrastructure for the active parity line. Windows archives
must not be published until the runtime and live-smoke gates in the exact tag
pass on x86_64.

## Host Requirements

Use a dedicated, disposable or tightly managed Windows build host with:

- native x86_64 Windows for `x86_64-pc-windows-msvc`;
- PowerShell 7 (`pwsh.exe`), Git for Windows, Python 3, CMake, and Rustup;
- Visual Studio Build Tools with the native MSVC C++ toolset and Windows SDK;
- one existing non-administrator local build account;
- an Azure NSG or external firewall that permits TCP/22 only from the Linux
  release host.

Windows ARM64 is deferred. Do not generate or publish ARM64 Windows archives
until the project has sustainable native ARM64 infrastructure and the complete
runtime and reproducibility matrix passes there.

For high-assurance releases, provision the builder from a measured disposable
image for each release and destroy it after collecting evidence. Reusing a
long-lived builder is operationally supported, but it is not equivalent to
rebuilding the host trust boundary for every release.

## One-Time Preparation

For a disposable Windows Server 2025 Desktop Experience host, first start
`sshd` and authorize the release machine's key for the initial Administrator
connection. Then run this from the trusted Linux release machine:

```bash
scripts/bootstrap_windows_release_builder.sh \
  WINDOWS_HOST ~/.ssh/windows-release-key PUBLIC_IP/32
```

The arguments are prompted for when omitted. The bootstrap verifies native
x86_64 Windows, derives the SSH public key, creates an allowed-signers policy
from the repository's configured Git SSH signing key, installs PowerShell 7,
Git, Python, CMake, the MSVC C++ workload, and pinned Rustup, creates the
non-administrator `fluxheim-build` account, and applies the hardened workspace,
SSH, and firewall policy below. The initial Administrator SSH access is removed
when that policy takes effect. Verify the SSH host-key fingerprint out of band
before treating a newly created builder as trusted.

The bootstrap uses `winget` and therefore expects Windows Server 2025 Desktop
Experience rather than Server Core. It downloads Rustup 1.29.1 from the
official Rust static archive and verifies the pinned SHA-256 before execution.
Rustup and Cargo remain writable by the dedicated build account, so their home
directories and executable directory are added only to that account's build
process environment. They are deliberately absent from the machine-wide
environment and `PATH`; the installer also removes obsolete machine-wide
entries when upgrading an existing builder. The release runner refuses to run
from an administrator token. Administrators that need Rust must use a separate
installation that the build account cannot modify.

To perform the policy step directly instead, open an elevated Windows
PowerShell session and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\prepare_windows_release_builder.ps1 `
  -ExpectedArchitecture X64 `
  -BuildUser fluxheim-build `
  -AuthorizedKeyFile C:\Bootstrap\linux-release-host.pub `
  -AllowedSourceCidr 203.0.113.10/32 `
  -TagAllowedSignersFile C:\Bootstrap\fluxheim-allowed-signers
```

Replace the documentation address with the Linux release host's real public
`/32` or a narrowly scoped IPv6 prefix. The script:

- verifies architecture and rejects an administrator build account;
- installs and enables Windows OpenSSH Server;
- prepends a global public-key-only policy, permits SSH login only for the
  dedicated build account with `AllowUsers`, points `AuthorizedKeysFile` at
  administrator-owned `C:\ProgramData\ssh\fluxheim-release\authorized_keys`,
  and keeps that policy outside any vendor `Match` block;
- grants the build identity read-only access to its SSH key and trusted tag
  signers, read/execute traversal on `C:\FluxheimBuild`, and Modify only below
  the precreated `runs` and `output` directories; trust roots and files are
  assigned to the local `Administrators` owner so a reused build-account-owned
  path cannot rewrite its DACL;
- narrows the Windows firewall rule to the supplied source CIDR;
- validates `sshd_config` before restart and prints host-key fingerprints;
- reports missing build tools without downloading floating installers.

Keep a custom `WorkspaceRoot` below administrator-controlled ancestors. The
release runner rejects any ancestor on which the build identity can delete the
directory or its children, change the DACL, or take ownership. Creating an
unrelated sibling is not rejected because it cannot replace an existing path
without one of those destructive rights. The default `C:\FluxheimBuild` layout
is designed for this policy.

Verify the printed SSH host-key fingerprint out of band before accepting it on
the Linux release machine. The Azure NSG remains a separate mandatory boundary;
the local Windows firewall rule is not a replacement for it.

## Exact-Tag Build

The Linux `release_helper.sh` can upload and invoke
`scripts/run_windows_release_builder.ps1` over OpenSSH. It passes the already
verified tag commit and downloads the resulting evidence. The Windows script
then independently:

1. fetches only the requested annotated tag, rejects OpenPGP, X.509, mixed, or
   duplicate signature armor, and verifies its sole SSH signature against the
   installed `allowed_signers` file at full trust;
2. proves that the build account cannot replace its SSH authorization, rename
   the trusted signer directory, replace `allowed_signers`, change trust-anchor
   content, ACLs, or ownership, or create a second trusted directory; content
   overwrite and append rights are checked independently, and every trust-path
   ancestor must be free of junctions and other reparse points and deny the
   build identity delete, DACL-change, and ownership rights;
3. checks the native Rust host architecture;
4. runs workspace tests and the mandatory native Windows live smoke;
5. builds all seven profiles twice with the PowerShell archive builder and
   launches every packaged executable to verify its version;
6. requires byte-identical ZIP hashes and emits checksums plus machine-readable
   commit, architecture, Windows edition/build, test-scope, and reproducibility
   evidence.

The script fails when `scripts/smoke_windows_native.ps1` is absent or any
native runtime assertion fails. This remains an intentional release block
until the complete 1.8.2 parity matrix passes on x86_64.

Windows outputs are unsigned `.zip` previews. Do not disable SmartScreen or
execution policy globally. Authenticode, MSI/MSIX, Store delivery, and service
installation remain later company-backed milestones.

## Optional Public PHP Ingress Smoke

The mandatory native smoke uses loopback listeners so it is deterministic and
does not require a public firewall exception. Before the first Windows release,
an operator can additionally prove off-host HTTP/HTTPS reachability and the
real external FastCGI path with:

```bash
scripts/smoke_windows_public_php.sh \
  WINDOWS_HOST ~/.ssh/windows-release-key \
  dist/fluxheim-${RELEASE_VERSION}-php-x86_64-windows.zip \
  windows-test.example.com
```

Run this from the trusted Linux release machine. The cloud firewall and Windows
Firewall must allow TCP/80 and TCP/443 from that machine. Alternate ports can
be selected with `FLUXHEIM_WINDOWS_PUBLIC_HTTP_PORT` and
`FLUXHEIM_WINDOWS_PUBLIC_HTTPS_PORT`. The test DNS name must already resolve to
the Windows host. Supply the public IP as the fifth argument when the SSH
hostname is not the address clients use.

The controller uploads the packaged `php` profile, starts it on the prepared
Windows host, and requests a real `index.php` over both public listeners. HTTPS
uses a short-lived private test CA and validates the supplied DNS name's SNI and
hostname rather than disabling certificate verification. The POST assertion
also proves request-body forwarding and PHP's `HTTPS`/`REQUEST_SCHEME` CGI
context.

The harness downloads the official PHP 8.4 NTS x86_64 archive and verifies its
pinned SHA-256 before executing `php-cgi.exe` as a loopback-only external
FastCGI server. PHP recommends NTS builds for FastCGI on Windows. This proves
Fluxheim's supported external FastCGI contract with a real PHP runtime; it does
not claim native Windows PHP-FPM or managed PHP-FPM support. The smoke is
opt-in because it requires public ingress and an external download. It removes
successful remote artifacts by default; set
`FLUXHEIM_WINDOWS_PUBLIC_SMOKE_KEEP=1` to retain them.

## Optional Public Packaged-Profile Matrix

The native loopback gate proves the complete runtime without opening test
services to the Internet. Before publishing the first Windows release, run a
separate off-host check against the exact packaged `proxy`, `load-balancer`,
`cache`, and `full` archives:

```bash
scripts/smoke_windows_public_profiles.sh \
  WINDOWS_HOST ~/.ssh/windows-release-key \
  dist/fluxheim-${RELEASE_VERSION}-proxy-x86_64-windows.zip \
  dist/fluxheim-${RELEASE_VERSION}-load-balancer-x86_64-windows.zip \
  dist/fluxheim-${RELEASE_VERSION}-cache-x86_64-windows.zip \
  dist/fluxheim-${RELEASE_VERSION}-full-x86_64-windows.zip \
  windows-test.example.com
```

The cloud firewall and Windows Firewall must permit TCP/80 and TCP/443. Supply
the public IP as the eighth argument when it differs from the SSH host. The
controller generates a short-lived private test CA and validates the public
hostname over HTTPS; it never disables certificate verification.

The matrix proves off-host proxying to a loopback-only origin, strict rejection
of an unknown Host, round-robin use of two load-balancer origins, failover after
one origin stops, a memory-cache `MISS` to `HIT`, and a persistent storage-bin
`HIT` after Fluxheim restarts with the origin offline. It finishes with static
HTTP/HTTPS delivery from the packaged `full` profile. Origins, control files,
and cache state are never exposed as public listeners. Successful artifacts are
removed unless `FLUXHEIM_WINDOWS_PUBLIC_SMOKE_KEEP=1` is set.

## Optional Public ACME Staging Smoke

After public HTTP/HTTPS reachability is proven, the same disposable builder can
exercise a real ACME HTTP-01 lifecycle with the packaged `full` profile:

```bash
scripts/smoke_windows_public_acme.sh \
  WINDOWS_HOST ~/.ssh/windows-release-key \
  dist/fluxheim-${RELEASE_VERSION}-full-x86_64-windows.zip \
  windows-test.example.com release-test@example.com \
  https://letsencrypt.org/documents/REVIEW-THE-CURRENT-TERMS.pdf
```

The final argument must be the exact Terms of Service URL currently advertised
by the Let's Encrypt staging directory and must be reviewed and supplied by the
operator. The script never silently accepts terms. The DNS name must resolve to
the Windows host, and both the cloud firewall and Windows Firewall must permit
public TCP/80 and TCP/443. Supply the public IP as the seventh argument when it
differs from the SSH host.

The harness uses a fresh isolated ACME storage directory, starts the packaged
Windows binary on public port 80, and requests one staging certificate. It then
restarts the same binary with HTTPS enabled. The Linux controller verifies the
HTTP and HTTPS content off-host, validates the presented certificate hostname,
and compares its SHA-256 fingerprint with the certificate Fluxheim installed.
Only Let's Encrypt staging is used; this test must never request a production
certificate or reuse production ACME state. Successful test state is removed
unless `FLUXHEIM_WINDOWS_PUBLIC_SMOKE_KEEP=1` is set.
