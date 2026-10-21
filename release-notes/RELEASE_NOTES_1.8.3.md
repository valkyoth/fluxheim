# Fluxheim 1.8.3 Release Notes

**Status: unreleased maintenance candidate.** The `1.8.x` branch starts at
v1.8.2. No v1.8.3 tag or published archives exist yet; final release gates,
pentest and GitHub approval remain required.

See the [candidate qualification record](../docs/maintenance-1.8.3-qualification.md)
for completed checks and remaining platform/release gates.

## Maintenance Scope

- Rust 1.99.1 and refreshed stable dependencies, including Tokio 1.54.1,
  Rustls 0.23.46, sanitization 2.1.1 and base64-ng 2.1.0.
- Wasmtime/WASI 50.0.0 for the explicit Wasm profile. Existing host-call,
  memory/fuel/timeout and fail-closed policy contracts remain in force.
  `full` still excludes Wasm. Modules must be trusted and integrity-pinned;
  sandboxing is not a reason to accept arbitrary untrusted deployment files.
- Refreshed immutable Rust and runtime container image digests, pinned Docker
  Actions, and checksum-verified Rustup 1.29.2 installers.
- Windows release-builder startup/evidence fixes. Read-only registry host
  metadata replaces the WMI query, avoiding manual WMI ACL grants.
- Rust 1.99's replacement atomic update API preserves UDP session admission
  ordering and limits without changing the configuration contract.

## Container Maintenance

The [runtime refresh workflow](../docs/container-runtime-refresh.md) rebuilds
the latest published release's containers with refreshed OS/PHP packages and
requires live smoke checks before promoting versioned image aliases. Unique
rebuild tags/digests identify each runtime. It does not rewrite source tags,
archive checksums, or Fluxheim's application version.

## Compatibility And Qualification

No new protocol, default feature profile, managed Windows PHP, management API
or observability redesign is introduced here. Windows stays x86_64 MSVC;
macOS stays Apple Silicon. Existing configs should remain valid.

The Wasmtime major update requires sandbox/policy regression tests, live
request tests and tests of the extracted Wasm release archive. Native Windows
and macOS archive/runtime checks must pass on this candidate, not merely on
the earlier 1.8.2 release. Full Linux profile/container and final release
checks also remain required before publication. See the
[maintenance policy](../docs/maintenance-releases.md).

Main stays at 1.9.0 for logging, metrics and operational visibility. HTTP/3
research is deferred there; it is absent from this release's dependency graph
and CI gates. Brynja/Vef are not production dependencies.
