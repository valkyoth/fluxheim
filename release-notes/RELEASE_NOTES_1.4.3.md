# Fluxheim 1.4.3 Release Notes

Fluxheim 1.4.3 is a maintenance architecture release. It does not add a new
operator-facing feature family; it splits the large configuration surface into
focused modules before the next `1.4.x` policy features.

## Highlights

- `config.rs` is reduced to the top-level serde facade, config merge and
  validation orchestration, shared `ConfigError`, and stable re-exports.
- Domain config now lives in focused files: `config_admin`, `config_acme`,
  `config_access`, `config_cache`, `config_compression`, `config_header`,
  `config_http`, `config_load_balance`, `config_logging`, `config_net`,
  `config_observability`, `config_path`, `config_php`, `config_proxy`,
  `config_route`, `config_server`, `config_tls`, and `config_web`.
- The large config unit-test module moved to `config_tests.rs`, keeping
  production `config.rs` small enough to review while preserving the same test
  coverage.
- Existing `crate::config::*` type paths are preserved for runtime modules and
  downstream internal callers.

## Security Hardening

- Path forwarding safety now rejects traversal that only appears after a third
  percent-decode pass, while still bounding decode work.
- Auth-request copied forwarded header values now use zeroizing storage after
  the subrequest completes.
- A private admin path helper was renamed so maintainers do not confuse the
  empty-path check with full traversal/symlink path validation.

## Compatibility Notes

- No configuration migration is required from 1.4.2.
- Operator-facing validation behavior is intended to be unchanged.
- This release intentionally does not add GeoIP, macOS production support,
  stream proxying, or new policy syntax.

## Suggested Checks

Run the normal release gates before publishing:

```bash
scripts/validate-release-metadata.sh
cargo check --locked --no-default-features --features profile-development --bin fluxheim --bin fluxheim-acme
cargo clippy --locked --no-default-features --features profile-development --all-targets -- -D warnings
```

For package validation, run the RPM build/smoke flow from
`docs/build-and-podman.md`.
