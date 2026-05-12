# Fluxheim 1.2.1 Release Notes

## Release Metadata

- Version: `1.2.1`
- Release date: 2026-05-12
- Git tag: `v1.2.1`
- Release type: focused cache follow-up

## Summary

Fluxheim `1.2.1` adds the focused local/static cache follow-up planned after
`1.2.0`. Operators can now opt local `[vhosts.web]` files and route-scoped web
actions into Fluxheim's cache policy model with `local_static = true`.

## Highlights

- Added explicit `local_static = true` cache-policy opt-in for local static
  vhost and route web responses.
- Local static cache keys include request identity plus file identity metadata,
  so updated files create new cache entries instead of reusing stale bodies.
- Local static cache responses can emit configured cache status and reason
  headers, including `MISS`, `HIT`, `BYPASS`, and `REVALIDATED`.
- Local static cache hits emit `Age`.
- Cache-key, cache-lookup, and exact-purge helpers now resolve local static
  files and use the same file-identity cache key when `local_static` is enabled.
- Memory storage is preferred when both memory and disk tiers are configured,
  avoiding a second disk copy of files already served from the local site root.
- The local static smoke test now verifies `MISS`, `HIT`, and `Age` behavior.

## Validated Scope

- Local gate passed before release prep:
  - `cargo check --features profile-observability,acme-client`
  - `cargo check --no-default-features --features proxy,web,cache,tls-rustls,security`
  - `cargo check --no-default-features --features proxy,cache,tls-rustls,security`
  - `cargo test --lib --features profile-observability,acme-client`
  - `cargo clippy --features profile-observability,acme-client --all-targets -- -D warnings`
  - `sh scripts/smoke_static_local.sh`
  - example config validation for `examples/vhosts.toml` and `examples/conf.d`
  - `git diff --check`
  - `rpmspec -q packaging/rpm/fluxheim.spec`

## Known Limits

- Local static cache storage currently admits full buffered static responses.
  Partial streaming admission remains reserved for a later cache storage pass.
- Slab/bin disk storage is planned for `1.2.2`.
- Distributed cache metadata and peer-fill are planned for `1.2.3`.
- Wasm-based extension points, including cache-rule hooks comparable to VCL/Lua
  style customization, are planned for `1.4`.

## Checksums And Signatures

Record during the release:

- Commit: to be filled after the release-prep commit
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
