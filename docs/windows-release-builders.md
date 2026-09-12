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
