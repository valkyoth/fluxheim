# Windows Release Builders

Fluxheim `1.8.2` uses separate native Windows x86_64 and ARM64 hosts for its
unsigned portable archive evidence. A Linux cross-build is not accepted as a
substitute for the native MSVC linker, Windows SDK, ACL, locking, shutdown, and
live-runtime checks.

This is release infrastructure for the active parity line. Windows archives
must not be published until the runtime and live-smoke gates in the exact tag
pass on both architectures.

## Host Requirements

Use a dedicated, disposable or tightly managed Windows build host with:

- native x86_64 Windows for `x86_64-pc-windows-msvc`, or native ARM64 Windows
  for `aarch64-pc-windows-msvc`;
- PowerShell 7 (`pwsh.exe`), Git for Windows, Python 3, CMake, and Rustup;
- Visual Studio Build Tools with the native MSVC C++ toolset and Windows SDK;
- one existing non-administrator local build account;
- an Azure NSG or external firewall that permits TCP/22 only from the Linux
  release host.

Azure may require a Windows 11 ARM64 image rather than Windows Server for the
ARM builder. Evidence must name the actual tested OS; it must not be presented
as Windows Server ARM support.

## One-Time Preparation

Sign in once as the dedicated build account so Windows creates its profile.
Then open an elevated Windows PowerShell session and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\prepare_windows_release_builder.ps1 `
  -ExpectedArchitecture X64 `
  -BuildUser fluxheim-build `
  -AuthorizedKeyFile C:\Bootstrap\linux-release-host.pub `
  -AllowedSourceCidr 203.0.113.10/32 `
  -TagAllowedSignersFile C:\Bootstrap\fluxheim-allowed-signers
```

Use `Arm64` on the ARM host. Replace the documentation address with the Linux
release host's real public `/32` or a narrowly scoped IPv6 prefix. The script:

- verifies architecture and rejects an administrator build account;
- installs and enables Windows OpenSSH Server;
- allows only public-key authentication for the build account;
- applies restrictive ACLs to `authorized_keys`, trusted tag signers, and
  `C:\FluxheimBuild`;
- narrows the Windows firewall rule to the supplied source CIDR;
- validates `sshd_config` before restart and prints host-key fingerprints;
- reports missing build tools without downloading floating installers.

Verify the printed SSH host-key fingerprint out of band before accepting it on
the Linux release machine. The Azure NSG remains a separate mandatory boundary;
the local Windows firewall rule is not a replacement for it.

## Exact-Tag Build

The Linux `release_helper.sh` can upload and invoke
`scripts/run_windows_release_builder.ps1` over OpenSSH. It passes the already
verified tag commit and downloads the resulting evidence. The Windows script
then independently:

1. fetches only the requested tag and verifies its SSH signature against the
   installed `allowed_signers` file;
2. checks the native Rust host architecture;
3. runs workspace tests and the mandatory native Windows live smoke;
4. builds all seven profiles twice with the PowerShell archive builder;
5. requires byte-identical ZIP hashes and emits checksums plus machine-readable
   commit, architecture, test-scope, and reproducibility evidence.

The script fails when `scripts/smoke_windows_native.ps1` is absent. That is an
intentional release block while the 1.8.2 runtime parity work is incomplete.

Windows outputs are unsigned `.zip` previews. Do not disable SmartScreen or
execution policy globally. Authenticode, MSI/MSIX, Store delivery, and service
installation remain later company-backed milestones.
