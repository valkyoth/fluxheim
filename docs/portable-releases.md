# Portable Releases

Fluxheim `1.8.0` establishes one portable archive contract for Linux, macOS,
and Windows. This is the packaging baseline for later platform-parity work; it
does not claim that every Linux deployment integration already has a native
equivalent on macOS or Windows.

## Archive Contract

Each supported operating-system target uses the same public profile names:

| Archive profile | Cargo feature set |
| --- | --- |
| `full` | `profile-full` plus ACME and observability exporters |
| `wasm` | `profile-wasm` plus ACME and observability exporters |
| `cache` | `profile-cache-edge` plus ACME |
| `proxy` | `profile-proxy-edge` plus ACME |
| `load-balancer` | `profile-load-balancer-edge` plus ACME |
| `php` | `profile-web-server`, PHP-FPM, and ACME |
| `config-tester` | `profile-development` |

`full` intentionally remains Wasm-free. Select `wasm` when in-process policy
execution and its reviewed proxy-ABI and WASI capability surfaces are needed.

Every staged directory is emitted internally as both `.tar.gz` and `.zip` so
the archive builder can verify that both formats contain the same paths and
file payloads. Publication format is platform-specific: Linux publishes
`.tar.gz`, unsigned macOS CLI previews publish `.tar.gz`, and Windows will
publish `.zip` once its native gate is complete. Windows binaries retain their
`.exe` suffix. Archive names use normalized platform labels such as:

```text
fluxheim-VERSION-wasm-x86_64-linux.tar.gz
fluxheim-VERSION-wasm-aarch64-macos.tar.gz
fluxheim-VERSION-wasm-x86_64-windows.zip
fluxheim-VERSION-wasm-aarch64-windows.zip
```

Windows uses the same naming contract during `1.8.2` development. Do not
publish those archives until the native runtime and release evidence gates pass
on both architectures.

The shared matrix can be inspected without compiling:

```bash
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | sed -n '1p')"
scripts/build_release_assets.sh "$VERSION" --kind linux --plan
scripts/build_release_assets.sh "$VERSION" --kind macos --plan
scripts/build_release_assets.sh "$VERSION" --kind windows --plan
python scripts/portable_release_plan.py "$VERSION" --kind windows --target aarch64-pc-windows-msvc
scripts/validate_portable_release_plan.py
```

The POSIX and PowerShell asset builders consume the same native Python
release-plan module. Plan validation and Windows packaging therefore do not
require Git Bash or WSL.

Build on the operating system and architecture represented by the target:

```bash
scripts/build_release_assets.sh "$VERSION" --kind macos --profile wasm
```

Cross-compiling a Windows MSVC binary from Linux is not an authoritative
release proof because the MSVC linker and Windows SDK are absent. The Windows
release builders must run natively on x86_64 and ARM64 hosts and use
`scripts/build_release_assets.ps1`. See
[Windows Release Builders](windows-release-builders.md). The same host-native
rule applies to Apple SDK and linker validation.

## Current Support Level

The `1.8.0` CI baseline compiled the portable static-site, reverse-proxy,
full, Wasm, and development profiles on native macOS and built representative
`full` and `wasm` archives. The `1.8.1` release gate runs on native Apple
Silicon, builds all seven public archive profiles for ARM64 macOS, and exercises
live static, proxy, downstream/upstream TLS, cache, admin, load-balancer, local
observability, and packaged Wasm behavior. Intel macOS is not a supported
release target and does not receive official archives.
External Prometheus and Jaeger collector integration remains in the Linux gate
because the macOS portable gate does not require a container runtime.

`1.8.0` did not publish Windows binaries. The active `1.8.2` line implements
native owner/ACL trust checks for configuration and runtime paths, Windows-safe
static and cache file handling, all seven MSVC profile builds, and native live
static, downstream/upstream TLS, memory and persistent disk cache, proxy,
load-balancer, admin, metrics, graceful-shutdown, external FastCGI, ACME
storage, and packaged-Wasm checks. Every packaged executable must also launch
and report the expected version. These checks preserve the existing trust
boundary instead of replacing it with permissive cross-platform fallbacks, and
must pass natively on both x86_64 and ARM64 before Windows archives are
published.

Live platform parity remains staged:

- `1.8.1` completes the defined unsigned native macOS runtime and archive
  smoke matrix while retaining explicit foreground and filesystem-policy
  limitations.
- `1.8.2` expands native Windows runtime and archive smoke coverage.
- `1.8.3` compares all published profiles and records intentional platform
  differences.

Linux-only deployment material can still be present inside an archive as
documentation, but it is not a native integration promise. In particular:

- systemd and RPM units are Linux deployment assets;
- the TCP admin listener is the portable Windows control plane; the local Unix
  operations socket is unavailable and must remain disabled;
- Unix socket activation, upgrade sockets, and certificate-reload sockets do
  not yet have Windows service/control-channel replacements;
- managed PHP-FPM process supervision is Unix-only, while external TCP
  FastCGI remains the portable PHP path;
- launchd and Windows service integration are later platform milestones.

Any profile that cannot meet its advertised platform contract must be called
out explicitly before release rather than silently omitted.

## Unsigned Preview Policy

macOS archives are unsigned portable previews until Fluxheim has company-backed
publisher credentials. Windows archives will follow the same policy when they
begin in `1.8.2`. SHA-256 checksums prove downloaded-byte integrity against the
published release metadata; they do not establish a signed publisher identity.

The public macOS preview uses only `.tar.gz`. Fluxheim is a command-line server,
and the documented terminal download and extraction flow avoids presenting an
unsigned ZIP as a Finder installation experience. ZIP remains an internal
archive-equivalence check and is not attached to the GitHub release. This is a
temporary distribution policy, not a substitute for Developer ID signing and
notarization.

Install a runtime profile without embedding a release number in automation:

```bash
VERSION="REPLACE_WITH_RELEASE_VERSION"
PROFILE="full"
ARCHIVE="fluxheim-${VERSION}-${PROFILE}-aarch64-macos.tar.gz"
BASE_URL="https://github.com/valkyoth/fluxheim/releases/download/v${VERSION}"

curl -fLO "${BASE_URL}/${ARCHIVE}"
curl -fLO "${BASE_URL}/SHA256SUMS-aarch64-macos.txt"
grep "  ${ARCHIVE}$" SHA256SUMS-aarch64-macos.txt | shasum -a 256 -c -
tar -xzf "$ARCHIVE"

install -d "$HOME/.local/bin"
install -m 0755 "fluxheim-${VERSION}-${PROFILE}-aarch64-macos/fluxheim" \
  "$HOME/.local/bin/fluxheim"
install -m 0755 "fluxheim-${VERSION}-${PROFILE}-aarch64-macos/fluxheim-acme" \
  "$HOME/.local/bin/fluxheim-acme"
```

Ensure `$HOME/.local/bin` is on `PATH`. The `config-tester` profile contains
`fluxheim-config-tester` instead of the two runtime binaries. Administrators
may install into `/usr/local/bin` with appropriate privileges instead.

Use the terminal workflow above even if the archive was first downloaded in a
browser. Do not disable Gatekeeper globally. If Finder or another graphical
extractor produces a quarantined executable, download and extract it again with
the documented command-line workflow. Signed and notarized `.pkg`/`.dmg`
installation is a later platform milestone.

Operators are responsible for local Gatekeeper, SmartScreen, ACL, and
execution-policy decisions for these unsigned archives. Fluxheim will not
recommend disabling platform security globally. Apple Developer ID
signing/notarization, Windows Authenticode, MSI/MSIX, and Store delivery remain
separate later milestones.

## Wasm Container Modules

The dedicated Wasm container does not embed operator modules. Mount a private
host directory read-only:

```yaml
volumes:
  - /srv/infra/fluxheim/plugins:/etc/fluxheim/plugins:ro,Z
```

Set `wasm.plugin_roots = ["/etc/fluxheim/plugins"]` and use hash-pinned plugin
configuration. A writable log mount such as `/var/log/fluxheim` is unrelated
to plugin loading and must not be reused as a plugin directory.

The read-only flag applies inside the container only. For high-assurance
deployments, build a derivative image containing reviewed modules and
non-secret configuration, pin both the Fluxheim base and deployed derivative
by manifest digest, and treat plugin changes as image releases. See
[Wasm Extensibility](wasm-extensibility.md#container-plugin-trust-models) for
the threat model and example.
