# Fluxheim 1.5.19 Release Notes

Fluxheim 1.5.19 moves the Fluxheim-owned load-balancer core into the internal
`fluxheim-load-balancer` workspace crate.

## What Changed

- Added `crates/fluxheim-load-balancer` as the internal owner of load-balancer
  backend snapshots, discovery adapters, active health checks, selection
  algorithms, runtime policy overrides, persistence, queue policy, state files,
  background task glue, and tests.
- Kept root `crate::load_balancer` as a compatibility shim so admin, proxy,
  runtime, status endpoints, release profiles, RPM/container packaging, and
  operator config syntax remain unchanged.
- Preserved the existing `profile-load-balancer-edge` image/profile and the
  full build's load-balancer support.
- Added narrow integration hooks for root-owned metrics recording and
  compliance HMAC signing, avoiding a dependency from the load-balancer crate
  back into proxy, admin, cache, web, or PHP internals.
- Kept the load-balancer crate's tests with the code they review, including
  selection, passive health, discovery, runtime mutation, persistence, and
  database/protocol health-check coverage.

## Compatibility

- Existing config files remain valid.
- Existing admin load-balancer status and mutation APIs remain unchanged.
- Existing feature profiles and release artifact names are unchanged.
- Existing RPM and container production feature sets are unchanged.
- `fluxheim-load-balancer` is an internal workspace crate and is not published
  to crates.io.

## Not Included

- No new load-balancer features in this release.
- No removal of `pingora-load-balancing` yet.
- No removal of `pingora-cache` yet.
- No cache, web, PHP, or HTTP proxy orchestrator crate extraction in this
  release.
- No production UDP/GSLB promotion, HTTP/3/QUIC, WAF, VPN/firewall appliance
  behavior, Wasm/iRules/Lua runtime, or full Pingora HTTP proxy replacement in
  this release.

## Packaging Notes

- Release assets continue to publish the same `full`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` artifacts.
- The load-balancer image remains the focused package for HTTP/TCP
  load-balancer deployments.
