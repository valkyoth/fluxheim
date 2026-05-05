# Changelog

All notable Fluxheim changes should be recorded here before a release tag is
created.

Fluxheim follows semantic versioning once `1.0.0` is released. Before `1.0.0`,
minor versions may still change configuration shape, feature names, and runtime
behavior when the change improves security or project direction.

## Unreleased

### Added

- GitHub CI, Dependabot, CodeQL, dependency policy, and release-check scripts.
- Feature preflight validation for mutually exclusive TLS backends and
  zero-retention privacy-mode incompatibilities.
- `profile-*` Cargo feature aliases for common build profiles.
- Zero-retention privacy example config for `profile-privacy` builds.

### Changed

- The default build is `proxy`, `web`, `cache`, `tls-rustls`, and `security`.
- Container builds can select both feature set and packaged config.

### Security

- Path and header handling are treated as release-gated areas with tests and
  CodeQL scanning.
- `privacy-mode` rejects access logging and cannot be combined with `cache` or
  `metrics`.

## 0.1.0 - Repository Baseline

### Added

- Initial Fluxheim Rust/Pingora project baseline.
- Modular static web, reverse proxy, cache, TLS, ACME planning, admin snapshot,
  load-balancer, metrics, logging, and privacy-mode foundations.
- EUPL-1.2 license, GitHub-ready README, roadmap, architecture docs, examples,
  and rootless Podman packaging.
- `deny.toml` and audit policy for license/advisory checks.

### Notes

- This is not a production `1.0` release. The stable `1.0` target remains
  static hosting, reverse proxying, vhosts, rustls TLS, secure defaults, and
  local/rootless Podman operation.
