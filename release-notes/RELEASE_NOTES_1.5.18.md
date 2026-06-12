# Fluxheim 1.5.18 Release Notes

Fluxheim 1.5.18 moves configuration ownership into the internal
`fluxheim-config` crate and hardens downstream HTTP/2 response handling.

## What Changed

- Added `crates/fluxheim-config` as the internal owner of config structs,
  parsing, validation, config-source loading, and config tests.
- Kept root `crate::config` and `crate::config_*` compatibility shims so
  runtime modules and operator-facing behavior stay stable.
- Preserved existing config syntax, config tester behavior, release profiles,
  RPM/container packaging, and artifact names.
- Added a config-crate `test-support` feature so root tests continue to use
  repository-local process paths while production defaults remain under
  `/run/fluxheim`.
- Added `proxy.downstream_total_response_timeout_secs`, an absolute HTTP/2
  response-write lifetime bound that is not reset by partial writes or client
  `WINDOW_UPDATE` frames.
- Clarified and tested that `server.limits.max_request_headers` counts
  duplicate request header values, including split HTTP/2 `Cookie` crumbs,
  before routing.

## Compatibility

- Existing config files remain valid.
- Existing feature profiles and release artifact names are unchanged.
- Omitted `proxy.downstream_total_response_timeout_secs` keeps the secure
  300-second default.
- The root `fluxheim` crate remains the binary/orchestration crate.
- `fluxheim-config` is an internal workspace crate and is not published to
  crates.io.

## Not Included

- No load-balancer crate extraction yet.
- No cache/web/PHP crate extraction yet.
- No removal of `pingora-load-balancing` or `pingora-cache` yet.
- No HTTP proxy runtime replacement, Wasm runtime, HTTP/3/QUIC, WAF, or
  production UDP/GSLB promotion in this release.

## Packaging Notes

- RPM and container production feature sets are unchanged.
- Release assets continue to publish the same `full`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` artifacts.
