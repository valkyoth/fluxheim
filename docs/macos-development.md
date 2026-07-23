# macOS Development Support

Fluxheim `1.4.4` established Level 1 macOS development support. Fluxheim
`1.8.0` adds the shared unsigned portable archive contract and native macOS CI
for representative `full` and `wasm` profiles. This remains a portable preview,
not a signed or notarized production package.

Linux remains the production baseline for native packages, systemd units,
containers, FIPS/ISO evidence, and complete release-gate parity. The native
Fluxheim runtime now removes the former Pingora portability qualification;
remaining work is macOS-specific live parity, filesystem-policy review,
service integration, signing, and notarization.

## Supported Scope

| Target | Scope |
| --- | --- |
| `aarch64-apple-darwin` | Primary Apple Silicon developer target for M-series Macs. |
| `x86_64-apple-darwin` | Intel Mac developer target when a maintainer can test it. |
| `aarch64-unknown-linux-gnu` | Linux ARM64 release target, released as `aarch64-linux`. |
| `x86_64-unknown-linux-gnu` | Main Linux production release target, released as `x86_64-linux`. |

ARM is not one release artifact. The Rust target triple defines the operating
system ABI and CPU baseline. For normal server ARM64 hardware such as Apple
Silicon, AWS Graviton, Ampere, and 64-bit Raspberry Pi operating systems, build
the matching `aarch64-*` target. Do not use `RUSTFLAGS="-C target-cpu=native"`
for published release assets unless the artifact is intentionally tied to one
machine class.

## Prerequisites

Install:

- Xcode Command Line Tools: `xcode-select --install`
- Rust 1.97.0 through rustup
- CMake if selecting native C dependencies such as zstd/libz-ng/AWS-LC paths
- Optional Homebrew PHP for managed PHP-FPM development tests

Check the host target:

```bash
rustc -vV | sed -n 's/^host: //p'
```

On an M-series Mac this should print `aarch64-apple-darwin`.

## Build Checks

These are the Level 1 developer checks:

```bash
cargo check --locked --no-default-features --features web --lib
cargo check --locked --no-default-features --features profile-static-site --bin fluxheim
cargo check --locked --no-default-features --features profile-reverse-proxy --bin fluxheim
cargo check --locked --no-default-features --features profile-full --bin fluxheim
cargo check --locked --no-default-features --features profile-wasm --bin fluxheim
cargo check --locked --no-default-features --features profile-development --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
```

For a quick runtime check:

```bash
sh scripts/smoke_macos_dev.sh
```

The smoke script writes all runtime state under `target/` by default and does
not touch `/run`, `/var/lib`, `/var/cache`, `/var/log`, launchd, or system
service locations.

## Local Runtime Paths

macOS development configs should use project-local paths, or a private
per-user temporary directory whose parents are not group/world writable:

| Runtime data | Recommended macOS dev path |
| --- | --- |
| pid file | `.fluxheim-dev/fluxheim.pid` |
| upgrade socket | `.fluxheim-dev/fluxheim-upgrade.sock` |
| certificate reload socket | `.fluxheim-dev/fluxheim-cert-reload.sock` |
| admin snapshots | `.fluxheim-dev/admin-snapshots` |
| ACME storage | `.fluxheim-dev/acme` |
| disk cache | `.fluxheim-dev/cache` |
| file logs | `.fluxheim-dev/logs/fluxheim.log` |
| managed PHP-FPM sockets | `.fluxheim-dev/php-fpm` |

Do not copy Linux service examples directly to macOS: `/run/fluxheim`,
`/var/lib/fluxheim`, `/var/cache/fluxheim`, and `/var/log/fluxheim` are
packaging defaults for Linux service deployments. Do not place Fluxheim runtime
state directly under `/tmp`; Fluxheim's filesystem trust checks reject
world-writable parents.

## Release Assets

Build the common portable profile matrix on macOS with:

```bash
RELEASE_VERSION=1.8.0
scripts/build_release_assets.sh "${RELEASE_VERSION}" --kind macos
```

This produces separate `full`, `wasm`, `cache`, `proxy`, `load-balancer`,
`php`, and `config-tester` archives in both `.tar.gz` and `.zip`. The older
combined developer archive remains available through `--kind macos-dev`.
Preferred portable naming examples:

- `fluxheim-1.8.0-full-aarch64-macos.tar.gz`
- `fluxheim-1.8.0-wasm-aarch64-macos.zip`
- `fluxheim-1.8.0-full-x86_64-macos.tar.gz`

Universal macOS binaries are optional and can be produced with `lipo` from
separate Intel and Apple Silicon builds, but per-target tarballs are simpler
and clearer for Fluxheim's current support level. See
[Portable Releases](portable-releases.md) for unsigned-preview limitations.
