# Contributing To Fluxheim

Fluxheim is a fun Rust/Pingora project, but it is still security-sensitive
infrastructure. Contributions are welcome when they keep the project small,
clear, tested, and honest about what is stable.

## License

Fluxheim is licensed under the European Union Public Licence 1.2. By
contributing, you agree that your contribution is provided under the same
license.

## Development Setup

Use the pinned Rust toolchain from `rust-toolchain.toml`.

```bash
cargo build
cargo test
```

Useful reduced builds:

```bash
cargo build --no-default-features --features proxy
cargo build --no-default-features --features web
cargo build --no-default-features --features profile-cache-edge
cargo build --no-default-features --features profile-proxy-edge
cargo build --no-default-features --features profile-development
cargo build --no-default-features --features profile-web-server,php-fpm
cargo build --no-default-features --features profile-privacy
cargo build --no-default-features --features profile-fips-openssl
```

When using a custom feature set, run the feature preflight first:

```bash
scripts/validate-features.sh proxy,web,tls-rustls
```

For OpenSSL FIPS-capable changes, run the dedicated fail-closed profile check:

```bash
scripts/validate-fips-openssl.sh check
```

## Checks

Before opening a pull request, run:

```bash
scripts/checks.sh
```

For release-sensitive changes, run:

```bash
scripts/release_checks.sh
```

Run the rootless Podman smoke when changing the container image or deployment
files:

```bash
FLUXHEIM_RELEASE_PODMAN=1 scripts/release_checks.sh
```

## Security-Sensitive Changes

Treat these areas as high risk:

- request parsing and body limits;
- TLS and certificate handling;
- proxy routing and upstream selection;
- cache keys, cache admission, and purge endpoints;
- admin API, snapshots, and rollback;
- logging, metrics, and privacy mode;
- dependency updates.

Do not post exploitable security details in public issues. Follow
[SECURITY.md](../SECURITY.md).

## Dependency Policy

Fluxheim uses `deny.toml`, `cargo-deny`, and `cargo-audit`.

When adding or updating crates:

- use crates.io releases unless there is a strong reason not to;
- avoid git dependencies;
- check maintenance status and license;
- keep `Cargo.lock` updated;
- run `cargo deny check` and `cargo audit`.

## Design Guidelines

- Prefer existing local patterns over new abstractions.
- Keep modules feature-gated when they change the threat model.
- Keep default builds focused on stable core behavior.
- Do not make legacy or experimental protocols part of normal request paths.
- Document stable, beta, experimental, and research features honestly.

## Pull Requests

Good pull requests are small enough to review and include:

- a clear summary;
- tests for behavior changes;
- docs or examples when user-facing behavior changes;
- security notes for risky areas.

Large features should start with a roadmap or design-doc update before code.
