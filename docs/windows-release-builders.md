# Windows Release Builders

Fluxheim `1.8.2` uses a native Windows x86_64 host for its unsigned portable
archive evidence. A Linux cross-build is not accepted as a substitute for the
native Windows ACL, locking, shutdown, and live-runtime checks.

This is release infrastructure for the supported unsigned Windows x86_64
portable line. Windows archives must not be published until the runtime and
live-smoke gates in the exact tag pass on x86_64.

## Host Requirements

Use a dedicated, disposable or tightly managed Windows build host with:

- native x86_64 Windows for `x86_64-pc-windows-msvc`;
- PowerShell 7 (`pwsh.exe`), Git for Windows, Python 3, CMake, and Rustup;
- Visual Studio Build Tools with the native MSVC C++ toolset and Windows SDK;
- an Azure NSG or external firewall that permits TCP/22 only from the Linux
  release host.

Windows ARM64 is deferred. Do not generate or publish ARM64 Windows archives
until the project has sustainable native ARM64 infrastructure and the complete
runtime and reproducibility matrix passes there.

Official release evidence requires a fresh disposable host provisioned from a
measured cloud image for that release. The runner rejects toolchains provisioned
more than 24 hours earlier. Destroy the host after collecting evidence.
Long-lived or reused Windows hosts may be used for development smoke tests, but
they cannot produce accepted release evidence.

The release-builder threat model assumes that this fresh host is single-tenant:
no untrusted local account, workload, startup script, or management agent may run
before or during provisioning and the release build. The bootstrap is not a
general-purpose hardening tool for shared or previously used Windows machines.
Its protected staging directory and dedicated build identity are defense in
depth for that narrow lifecycle; they do not make a compromised host trustworthy.
The native GitHub Windows job remains an independent test environment, but its
archives are CI evidence rather than a second publication source. This matches
the Linux ARM release model: publish the exact-tag archives produced by the
disposable native host after their checksums and native smoke evidence pass.

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
when that policy takes effect. Before reporting success, bootstrap runs the real
release runner in `-ValidateBuilderOnly` mode to verify every compiler file,
directory, hash, ACL, and sanitized compiler selection without requiring a
release tag. Verify the SSH host-key fingerprint out of band before treating a
newly created builder as trusted.

Administrator bootstrap files are staged at
`C:\Users\Administrator\FluxheimBootstrap`, inside the protected profile of
the initial Administrator account. Provisioning fails if a file, directory,
junction, or other object already occupies that path; it never adopts or
repairs a pre-existing staging directory. The directory is created without
`-Force` before any upload and is restricted to Administrators and SYSTEM. If
this check fails, discard the VM instead of deleting the object and retrying on
the same host. Official provisioning assumes the standard Administrator
profile path supplied by the required fresh Windows Server image.

The bootstrap uses `winget` and therefore expects Windows Server 2025 Desktop
Experience rather than Server Core. It downloads Rustup 1.29.1 from the
official Rust static archive and verifies the pinned SHA-256 before execution.
Administrator installs the exact pinned Rust toolchain under
`C:\Program Files\FluxheimRustTrusted`, records hashes for every installed file,
and keeps the tree Administrator/SYSTEM-only during installation before
recursively granting the build account read/execute access. Rustup's bootstrap
proxy directory is removed before that inventory is sealed because release
builds execute Cargo directly from the versioned toolchain. The release runner
verifies the manifest, every file hash, every file and directory ACL, and
non-reparse-point ancestry before source checkout. It never invokes Rustup,
ignores user-level executable search paths, clears inherited Rust/Cargo
overrides, and creates a fresh Cargo home inside each run. The trusted root must
not already exist when a builder is provisioned; use a new host rather than
reusing or repairing it for an official release.

The verifier permits the standard Windows volume-root right to create unrelated
directories. It still requires every non-root ancestor to deny child creation
and every ancestor, including the volume root, to deny deletion, child
replacement, ACL changes, and ownership changes by the build account.

The bootstrap supports a fresh OpenSSH Users group and refreshes its elevated
process environment after `winget` installs the native prerequisites. The
stock OpenSSH `Match Group administrators` key-file override may still appear
when inspecting the initial Administrator session; the generated global
`AllowUsers fluxheim-build` policy excludes that account, and the bootstrap
proves that Administrator SSH is rejected before it reports success.

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

An operator-owned Linux aggregator can transfer and invoke
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
4. verifies the Administrator-provisioned toolchain inventory, read-only ACL,
   fresh-disposable marker, and 24-hour age limit, then creates an isolated
   per-run Cargo home and reconstructs the process environment from an
   allowlist;
5. runs workspace tests and the mandatory native Windows live smoke;
6. builds the default release binary in two clean target directories and
   requires identical SHA-256 hashes, matching the Linux and macOS
   reproducibility check;
7. builds all seven profiles once, launches every packaged executable to verify
   its version, and emits archive checksums plus machine-readable commit,
   architecture, Windows edition/build, toolchain-manifest hash, test-scope,
   and reproducibility evidence. The hashed provisioning manifest is retained
   with the output so it remains auditable after host destruction.

Cargo always runs from the Administrator-controlled `cargo-work` directory and
receives the authenticated checkout through an explicit `--manifest-path`.
The runner rejects `.cargo/config` and `.cargo/config.toml` in checkout
ancestors. This prevents a previous build from persisting a compiler wrapper;
the per-run Cargo home prevents cross-run Cargo configuration or cache state.

The repository `scripts/release_helper.sh` invokes this builder over SSH,
downloads its seven ZIPs and evidence, verifies their checksums and commit, and
adds them to the same release report as Linux and imported macOS assets. The
GitHub-hosted `windows-2025` job separately runs the native test and archive
matrix. It does not need to reproduce the cloud builder's archive bytes.

The script fails when `scripts/smoke_windows_native.ps1` is absent or any
native runtime assertion fails. Every 1.8.2 release build therefore remains
blocked unless the complete parity matrix passes on x86_64.

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
