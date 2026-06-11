# Fluxheim 1.5.17 Release Notes

Fluxheim 1.5.17 starts the workspace and shared-crate foundation line.

This release is intentionally structural. It creates the first internal
workspace crate without changing operator-facing config, runtime behavior, or
release profiles. The goal is to make later config, load-balancer, cache, web,
PHP-FPM, Wasm, and runtime extractions smaller and safer.

## What Changed

- Converted the repository into a Cargo workspace.
- Added `crates/fluxheim-common` as the first internal shared crate.
- Moved the Fluxheim-owned `FluxError` and `FluxResult` boundary into
  `fluxheim-common`.
- Moved shared forward-path safety validation into `fluxheim-common`.
- Moved repository-local test path helpers behind the `fluxheim-common`
  `test-support` feature.
- Kept root compatibility adapters at `crate::flux_error` and
  `crate::path_safety`, plus the test-only `crate::test_support` adapter, so
  existing modules and tests continue to compile without broad churn.
- Kept Pingora-specific error conversion at the root adapter boundary instead
  of moving Pingora dependencies into the common crate.
- Updated `regex` from `1.12.3` to `1.12.4`.
- Added a release-gate crate freshness check for compatible non-Pingora updates
  and stricter release metadata checks for release notes, README,
  build/container docs, and RPM version alignment.
- Copied workspace crates into all container build stages so release images
  build correctly after the workspace split.
- Made `scripts/stable_release_gate.sh release` require the root image smoke
  plus representative Debian and Alpine variant image smokes before tagging.
- Fixed the vendored OpenSSL FIPS support build script so Rust 1.96 clippy
  accepts the crate under release `-D warnings` checks.

## Compatibility

- No config syntax changes.
- No runtime behavior changes.
- Existing feature profiles and release artifact names are unchanged.
- The root `fluxheim` crate remains the binary/orchestration crate.
- `fluxheim-common` is an internal workspace crate and is not published to
  crates.io.

## Not Included

- No config crate extraction yet.
- No load-balancer crate extraction yet.
- No cache/web/PHP crate extraction yet.
- No removal of `pingora-load-balancing` or `pingora-cache` yet.
- No HTTP proxy runtime replacement, Wasm runtime, HTTP/3/QUIC, WAF, or
  production UDP/GSLB promotion in this release.

## Packaging Notes

- RPM and container production feature sets are unchanged.
- Release assets continue to publish the same `full`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` artifacts.
