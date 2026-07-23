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

Every staged directory is emitted as both `.tar.gz` and `.zip`. The archive
builder verifies that both formats contain the same paths and file payloads.
Windows binaries retain their `.exe` suffix. Archive names use normalized
platform labels such as:

```text
fluxheim-1.8.0-wasm-x86_64-linux.zip
fluxheim-1.8.0-wasm-aarch64-macos.tar.gz
```

Windows will use the same naming contract from `1.8.2`; `1.8.0` does not
publish a Windows archive.

The shared matrix can be inspected without compiling:

```bash
scripts/build_release_assets.sh 1.8.0 --kind linux --plan
scripts/build_release_assets.sh 1.8.0 --kind macos --plan
scripts/build_release_assets.sh 1.8.0 --kind windows --plan
scripts/validate_portable_release_plan.py
```

The shell asset builder and cross-platform validator consume the same native
Python release-plan module. Plan validation therefore does not require Bash,
Git Bash, or WSL on Windows.

Build on the operating system and architecture represented by the target:

```bash
scripts/build_release_assets.sh 1.8.0 --kind macos --profile wasm
```

Cross-compiling a Windows MSVC binary from Linux is not an authoritative
release proof because the MSVC linker and Windows SDK are absent. The Windows
CI runner validates the shared archive plan and fail-closed configuration
boundary in `1.8.0`; native Windows runtime and archive builds begin with the
`1.8.2` parity work. The same host-native rule applies to Apple SDK and linker
validation: published macOS archives must be built on macOS.

## Current Support Level

The `1.8.0` CI baseline compiles the portable static-site, reverse-proxy,
full, Wasm, and development profiles on native macOS, and builds representative
macOS `full` and `wasm` archives. The complete seven-profile naming and feature
contract is checked without compiling on every supported CI host.

`1.8.0` does not publish Windows binaries. Fluxheim deliberately rejects
configuration-file loading on Windows until native owner and ACL trust checks
replace the Unix ownership and mode checks, and the cache storage path still
depends on descriptor-relative Unix filesystem operations. It does not
silently weaken either security boundary to make a preview compile. The
Windows CI planning gate validates archive names and feature sets and executes
a platform-specific regression proving unsupported config trust checks fail
closed. Runtime config loading, path trust, cache storage, service integration,
profile builds, and archives are `1.8.2` work.

Live platform parity remains staged:

- `1.8.1` expands native macOS runtime and archive smoke coverage.
- `1.8.2` expands native Windows runtime and archive smoke coverage.
- `1.8.3` compares all published profiles and records intentional platform
  differences.

Linux-only deployment material can still be present inside an archive as
documentation, but it is not a native integration promise. In particular:

- systemd and RPM units are Linux deployment assets;
- Windows does not support Unix-domain control paths in the same way as Linux;
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
