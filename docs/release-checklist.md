# Release Checklist

Use this checklist before publishing a Fluxheim release, changing dependency
versions, changing TLS/cache/proxy behavior, or building an image for other
people to run.

## Version And Toolchain

- Confirm the Rust version in `rust-toolchain.toml`, `Cargo.toml`, `README.md`,
  and the `Containerfile` all agree.
- Check that the pinned Rust version is still the current stable release before
  release work starts.
- Re-check the latest `cargo-deny` and `cargo-audit` versions:

```bash
cargo info cargo-deny
cargo info cargo-audit
```

Install or update the tools with locked dependency resolution:

```bash
cargo install --locked cargo-deny
cargo install --locked cargo-audit
```

## Dependency, License, And Advisory Gates

- Run `cargo update` only as a deliberate dependency maintenance step.
- Review every new dependency for maintenance status and SPDX license metadata.
- Keep `deny.toml` strict: unknown registries, git sources, and unknown licenses
  stay denied.
- Keep `.cargo/audit.toml` exceptions narrow, versioned, and documented with a
  removal condition.
- Run the release wrapper:

```bash
scripts/release_checks.sh
```

The wrapper runs formatting, clippy, tests, selected feature builds, example
config validation, `cargo deny check`, and `cargo audit`.

## TLS And Certificate Storage

- Static certificate chains and private keys are supported. Bought certificates
  remain a first-class deployment mode.
- ACME config and renewal queue planning are implemented, but account/order and
  challenge runtime work is not release-ready yet. Do not document automated
  ACME issuance as operational until that runtime is implemented and tested.
- Validate production-like TLS storage before startup:

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

On Unix, private keys should be owner-only (`0600`) and ACME storage directories
should be owner-only (`0700`).

## Build Matrix

Confirm the default binary and important reduced binaries compile:

```bash
cargo build --release
cargo build --release --no-default-features --features proxy
cargo build --release --no-default-features --features proxy,load-balancer
cargo build --release --no-default-features --features web
cargo build --release --no-default-features --features cache
```

For hardware-specific local binaries, use `target-cpu=native` only for the
machine that will run the binary. Do not publish those binaries as portable
artifacts:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Rootless Podman

Run the Podman smoke before publishing a container image:

```bash
FLUXHEIM_RELEASE_PODMAN=1 scripts/release_checks.sh
```

If Codex or another sandboxed tool cannot reach the rootless socket, export the
socket explicitly:

```bash
CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock" scripts/podman_smoke.sh
```

The smoke builds the image, validates the packaged config, and checks that the
runtime process does not run as root.

## Final Release Gate

- Confirm `git status` contains only intentional release changes.
- Update release notes or changelog material before tagging.
- Confirm the repository still carries the `EUPL-1.2` license.
- Confirm reviewed advisory exceptions still match current `cargo audit`
  output.
