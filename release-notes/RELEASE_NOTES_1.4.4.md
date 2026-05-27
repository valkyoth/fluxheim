# Fluxheim 1.4.4 Release Notes

Fluxheim 1.4.4 is the Apple Silicon macOS Level 1 developer-support release.
It is scoped to local contributor builds, Mac-safe runtime paths, and a small
macOS developer smoke gate.

## Highlights

- Add a macOS developer support document covering Apple Silicon and Intel Mac
  target triples, local prerequisites, build commands, smoke testing, and
  release-asset naming.
- Add `examples/macos-dev.toml`, which keeps pid files, sockets, snapshots,
  ACME storage, cache, logs, and web roots under `.fluxheim-dev`.
- Add `scripts/smoke_macos_dev.sh`, a local static-site runtime smoke that
  writes all state under `target/` by default.
- Add a GitHub Actions Apple Silicon developer gate on `macos-15` for the
  supported development profile checks.
- Document macOS developer release artifacts as target-triple tarballs rather
  than Linux production packages.
- Add `scripts/build_release_assets.sh` so release archives use normalized
  platform labels such as `x86_64-linux`, `aarch64-linux`, and
  `aarch64-macos`.

## Compatibility Notes

- Linux remains the production support baseline.
- macOS support is developer-level only in this release. It is not a FIPS/ISO
  evidence claim, not a launchd/Homebrew packaging milestone, and not a
  notarized-binary support claim.
- ARM release artifacts are target-specific: `aarch64-macos` for Apple Silicon
  macOS developer builds and `aarch64-linux` for Linux ARM64 production
  builds.

## Suggested Checks

On an M-series Mac:

```bash
cargo check --locked --no-default-features --features web --lib
cargo check --locked --no-default-features --features profile-static-site --bin fluxheim
cargo check --locked --no-default-features --features profile-reverse-proxy --bin fluxheim
cargo check --locked --no-default-features --features profile-full --bin fluxheim
cargo check --locked --no-default-features --features profile-development --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester
sh scripts/smoke_macos_dev.sh
```
