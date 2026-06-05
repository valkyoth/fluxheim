# Fluxheim 1.5.5 Release Notes

Fluxheim 1.5.5 starts the Fluxheim-native HTTP/error type boundary line. The
goal is to standardize internal modules on owned HTTP and error surfaces while
keeping narrow Pingora adapters at the current runtime boundaries.

## Changed

- Add `http_types` as the internal standard HTTP type boundary.
- Re-export standard `http` crate method, URI, status, version, response, and
  header types for internal modules.
- Keep Pingora request/response header wrappers named explicitly as adapter
  types at ingress/runtime boundaries.
- Add a `thiserror`-backed `FluxError` / `FluxResult` internal error surface.
- Convert the upstream PROXY-protocol connector to use `FluxResult` internally
  and convert back to Pingora errors only at the connector trait boundary.
- Move selected access-log, auth-request, compression, PHP-FPM, route-policy,
  traffic-mirror, proxy-cache, load-balancer, and proxy imports through the new
  HTTP boundary aliases.
- Extend the HTTP boundary aliases into load-balancer health checks,
  persistence-cookie parsing, and static web response builders.
- Move load-balancer tests, access-log tests, and the cache-key CLI request
  builder through the explicit Pingora request-header adapter alias.
- Route response-compression initialization errors and cache range/slice key
  validation errors through `FluxError` before adapting them back to Pingora
  errors.
- Keep proxy request/response adapter aliases available across all proxy
  profiles so the Apple Silicon macOS developer CI matrix can check
  `web`, `profile-static-site`, `profile-reverse-proxy`, `profile-full`, and
  `profile-development` without feature-gate drift.

## Boundaries

1.5.5 does not replace the HTTP proxy runtime, stream proxy runtime, cache
semantics, load-balancer selection/state behavior, HTTP/3/QUIC, UDP/GSLB, WAF,
VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting.
