# Fluxheim

Fluxheim is planned as a modular Rust reverse proxy built on Pingora. The
default binary will include proxying, caching, static file serving, TLS, ACME,
metrics, and security controls. Each major capability is feature-gated so a
smaller binary can be compiled when only one role is needed.

## Current Baseline

- Rust stable: `1.95.0`
- Rust edition: `2024`
- License: `EUPL-1.2`
- Dependency policy: `deny.toml`

## Feature Flags

Default build:

```bash
cargo build
```

Proxy-only build:

```bash
cargo build --no-default-features --features proxy
```

Static web server-only build:

```bash
cargo build --no-default-features --features web
```

## Required Checks

Run these before committing dependency or security-sensitive changes:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
cargo audit
```

Install the security tools with locked versions from crates.io:

```bash
cargo install --locked cargo-deny
cargo install --locked cargo-audit
```

The latest versions verified on May 4, 2026 were `cargo-deny 0.19.4` and
`cargo-audit 0.22.1`.

## Dependency Rules

- Check crates.io/docs.rs before adding or upgrading dependencies.
- Prefer maintained crates with clear SPDX license metadata.
- Keep dependencies compatible with `EUPL-1.2`.
- Do not add git dependencies unless pinned by revision and reviewed.
- Run `cargo deny check licenses` after dependency changes.
- Run `cargo audit` regularly and before releases.
