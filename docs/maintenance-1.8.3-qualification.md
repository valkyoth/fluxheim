# 1.8.3 Maintenance Qualification

Candidate preparation date: 2026-10-21. **Not release approval.**

## Provenance And Scope

- Branch `1.8.x` starts at signed release v1.8.2,
  `6ed82b5a9ebd5b8f1bb4bc03f986edd9a33ae855`.
- Selected maintenance files come from main `792cd9d2`, including prior
  Windows helper/evidence fixes and container refresh tooling. The protocol
  probes, HTTP/3 source gate and 1.9 observability implementation plan are not
  included. Version fields and maintenance release documentation are specific
  to 1.8.3.
- External production dependency name/version pairs match the tested main
  graph; Fluxheim package versions differ intentionally. The only first-party
  runtime source change from v1.8.2 is the equivalent Rust 1.99 atomic API
  spelling in UDP session admission.

## Refresh Inventory

Rust stable was checked against the official
[toolchain manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml):
1.99.1. Rustup 1.29.2 Linux and Windows installers were downloaded and their
SHA-256 hashes compared with the official archive checksum files before pinning.
Workspace and fuzz dependency locks were refreshed through Cargo; direct
workspace dependency freshness was checked with `cargo outdated --workspace
--depth 1`.

Notable versions: Wasmtime/WASI 50.0.0 (v1.8.2 used 48.0.2), Tokio 1.54.1,
Rustls 0.23.46, sanitization 2.1.1, base64-ng 2.1.0. No prerelease provider or
QUIC library was admitted. The vendored instant-acme patch remains unchanged
and its checksum policy passes.

GitHub Actions were checked against upstream releases and retain immutable
commit pins: checkout 7.0.1, QEMU 4.4.0, Buildx 4.4.1, build-push 7.4.0, login
4.6.0. cargo-deny 0.20.2, cargo-audit 0.22.2, cargo-sbom 0.10.0 and PyYAML
6.0.3 remain current in the configured tooling. Actionlint 1.7.12 was used for
validation. All runtime/Rust/UBI container base digests were resolved afresh
within the existing OS release lines; this is not an OS-major migration.

The isolated HTTP/3 research pins on main remain intentionally historical;
they are not maintained production dependencies. Legacy external smoke
fixture release lines (for example the Jaeger v1 fixture) are not promoted
to new major versions in this maintenance patch.

## Local Evidence

Linux x86_64, Rust 1.99.1, candidate working tree before commit. Test-built
archives/images are development evidence, not signed-tag release artifacts.

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked --features profile-development,wasm-proxy-abi,wasm-wasi,udp-proxy` | 2,078 passed; one mount-namespace test ignored in this invocation |
| `cargo test --workspace --locked` | 1,761 passed; one mount-namespace test ignored in this invocation |
| `sh scripts/smoke_acme_mount_boundary.sh` | The isolated mount test passed separately |
| Workspace/all-targets Clippy with the same features and `-D warnings` | Passed |
| `cargo fmt --all --check` | Passed |
| `cargo check --locked --manifest-path fuzz/Cargo.toml` | Passed; not a fuzz campaign |
| `cargo audit`, production and fuzz locks | Passed; no known advisories reported |
| `cargo deny --locked check` | Advisories, bans, licenses and sources passed |
| `cargo outdated --workspace --depth 1` | No newer direct dependencies reported |
| `sh scripts/smoke_wasm_release_asset.sh` | Linux Wasm tar.gz/ZIP built; extracted binary passed live policy examples |
| `sh scripts/smoke_1_0_core.sh` | Profile checks and live static/proxy/TLS passed |
| `sh scripts/smoke_upstream_tls_local.sh` | Verified upstream HTTPS passed |
| `cargo check --locked --no-default-features --features profile-fips-rustls` | Passed; not live provider/compliance evidence |
| Same check with `profile-fips-openssl` | Passed; not live provider/compliance evidence |
| Container refresh regressions | 15 passed |
| Windows scripts/security audit, portable plan, Wasm profile, PHP image plan | Passed |
| Release metadata/helpers, FIPS plan, vendored patch, modularity, Markdown links | Passed |
| Actionlint 1.7.12 on all four workflows; Git whitespace integrity | Passed |
| `sh scripts/smoke_wasm_container.sh` | Passed; live policy execution from a read-only module mount |
| `FLUXHEIM_PHP_IMAGE_VARIANTS=wolfi sh scripts/smoke_fluxheim_php_images.sh` | Passed; PHP 8.5.12 extension checks and live managed PHP-FPM response |

## Remaining Release Gates

Run pentest/retest from v1.8.2 to the final candidate and wait for GitHub green
on `1.8.x`. Native Windows x86_64 and Apple Silicon macOS archive/runtime gates
have not been executed in this Linux preparation pass. Linux ARM64 and the
complete image/profile matrix, full stable/deep release gates, reproducibility,
SBOM and final publication evidence remain release work. No tag, push, image
publication or official release upload was performed here.

Wasm 50 must pass those native/platform gates as well as the Linux sandbox and
policy tests; matching Linux behavior is not proof of Windows/macOS parity.
Rebuild release artifacts from the final approved signed tag, not from the
dirty-tree smoke outputs produced during this preparation.
