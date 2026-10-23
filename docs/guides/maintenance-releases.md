# Maintenance Releases

`main` is the unreleased 1.9.0 logging, metrics and operational visibility
development line. `1.8.x` started from the signed v1.8.2 release and delivered
v1.8.3 at `14d7b6cfc9b16c39a8dc0d4770f59290c8feea48`. Keep it available for
reviewed maintenance while 1.9.0 develops. See the
[1.8.3 qualification record](../evidence/maintenance-1.8.3-qualification.md).

## Scope

Backport reviewed bug/security fixes, dependency/toolchain updates, container
runtime refreshes and release-helper fixes. Do not merge unfinished main
features, protocol probes or future planning into a maintenance release.
Keep relevant fixes on both lines and record the source commit or selected
file set in the maintenance commit/evidence.

A major dependency version is not automatically disallowed, but it requires
reviewed compatibility and security evidence. For the Wasmtime 50 update,
test runtime/WASI sandbox limits, traps and fail-closed behavior, all policy
families, Wasm routing/cache integration and extracted release binaries. A
successful compile alone is insufficient. `full` must remain Wasm-free.

## Gates

Both `main` and `1.8.x` pushes/pull requests run Rust CI. Run the same local
metadata, feature/profile, lint, workspace, audit and live smoke gates on the
maintenance candidate. Incremental pentest and green GitHub checks are
required before tagging. Retest affected Windows and Apple Silicon macOS
archives natively; Linux cross-compilation is not equivalent.

Only a reviewed release commit may become a signed v1.8.x tag. Build artifacts
from that tag, record exact commits/checksums and preserve normal publication
checks. Never retag v1.8.2 or publish candidate assets as an existing release.
Version markers and draft notes do not constitute release approval.

## Containers

The runtime refresh workflow follows the latest published stable release, not
the unreleased branch HEAD. With 1.8.3 published it selects that stable release,
subject to its independent trust/protected-environment prerequisites.
It does not automatically maintain
multiple old release lines after a newer stable line exists. Separate support
policy and explicit selection would be needed for that behavior.

OS/PHP refreshes do not change Fluxheim's application version. A new Rust
dependency/toolchain build does change the application build and belongs in
a new maintenance release, not a runtime-only rebuild of an existing tag.
