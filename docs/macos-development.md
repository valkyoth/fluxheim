# macOS Development Support

Fluxheim `1.4.4` established Level 1 macOS development support. Fluxheim
`1.8.0` added the shared unsigned portable archive contract. Fluxheim `1.8.1`
builds every public archive profile in native Apple Silicon CI and expands the
live macOS parity suite. Intel macOS is not a supported release target. This
remains a portable preview, not a signed or notarized production package.

Linux remains the production baseline for native packages, systemd units,
containers, FIPS/ISO evidence, and complete release-gate parity. The native
Fluxheim runtime now removes the former Pingora portability qualification;
the `1.8.1` native matrix and documented filesystem boundary close the planned
portable parity scope. Native service integration, extended-ACL enforcement,
signing, and notarization remain later work.

## Supported Scope

| Target | Scope |
| --- | --- |
| `aarch64-apple-darwin` | Primary Apple Silicon developer target for M-series Macs. |
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
- Rust 1.98.0 through rustup
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

Run the native subsystem parity suite with:

```bash
sh scripts/smoke_macos_native_parity.sh
```

This exercises live static and proxy serving, downstream TLS, verified
upstream TLS with a temporary private CA, local static and proxy cache,
admin operations, load balancing, and local metrics/exporter health. Native
CI then executes all four Wasm policy examples through the binary staged in
the `wasm` archive. The macOS suite deliberately does not launch disposable
Prometheus or Jaeger containers; the Linux release gate retains that external
collector integration proof.

The verified upstream TLS path can also be run independently:

```bash
sh scripts/smoke_upstream_tls_local.sh
```

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

## Foreground Deployment

Fluxheim `1.8.1` supports an explicitly foreground macOS deployment mode. Run
the portable binary under a user-selected process supervisor:

```bash
./fluxheim --config "$HOME/.config/fluxheim/fluxheim.toml"
```

Keep `[server.process].daemon = false` and send `SIGTERM` for bounded graceful
shutdown. Fluxheim does not yet ship or claim a supported launchd service
definition; signing, notarization, launchd packaging, and privileged-port
installation remain later `1.8` work.

## APFS, ACL, And Symlink Boundaries

macOS is a Unix target, so Fluxheim applies the same owner, POSIX mode, path
depth, and no-follow checks used by its trusted configuration and secret
loaders. Trusted inputs must be owned by root or the Fluxheim process user,
must not have group/world write mode bits, and must not traverse symlinks.

Default APFS volumes are commonly case-insensitive. Do not create config,
certificate, cache, snapshot, or Wasm paths that differ only by letter case;
Fluxheim treats the filesystem's resolved identity as authoritative. Keep
cache, snapshot, and ACME state on a local filesystem with reliable advisory
locking and atomic rename behavior.

The generic Unix trust helper validates ownership and POSIX mode bits but does
not enumerate macOS extended ACL entries. Before using a portable archive for
a high-assurance deployment, inspect trusted paths with `ls -le` and remove
ACL grants that let another account modify them. This is an operator boundary
of the unsigned portable preview, not a claim of complete macOS ACL policy
validation.

## Release Assets

Build the common portable profile matrix on macOS with:

```bash
RELEASE_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | sed -n '1p')"
scripts/build_release_assets.sh "${RELEASE_VERSION}" --kind macos
```

This produces separate `full`, `wasm`, `cache`, `proxy`, `load-balancer`,
`php`, and `config-tester` archives. The builder creates both `.tar.gz` and
`.zip` internally and proves that their payloads match. Only `.tar.gz` is
published for the unsigned macOS CLI preview; ZIP is validation-only until
Fluxheim can ship a Developer ID-signed and notarized installer. The older
combined developer archive remains available through `--kind macos-dev` but
is not a public release asset. Portable naming is version-independent:

- `fluxheim-VERSION-full-aarch64-macos.tar.gz`
- `fluxheim-VERSION-wasm-aarch64-macos.tar.gz`

Fluxheim does not publish Intel or universal macOS binaries. See [Portable
Releases](portable-releases.md) for unsigned-preview limitations.

For installation, checksum verification, Gatekeeper boundaries, and the
terminal-only preview workflow, follow the
[Unsigned Preview Policy](portable-releases.md#unsigned-preview-policy). Do not
present these archives as a Finder installer or advise users to disable
platform security. A signed/notarized graphical installation workflow replaces
this temporary preview policy once publisher credentials are available.
