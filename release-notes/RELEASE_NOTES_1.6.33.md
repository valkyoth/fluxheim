# Fluxheim 1.6.33 Release Notes

Fluxheim 1.6.33 is the native proxy-cache parity release in the Pingora
removal line.

This first checkpoint adds Fluxheim-owned native memory-cache support for
ordinary HTTP/1 proxy responses. Disk cache, slice cache,
stale-while-revalidate, peer-fill, and predictor remain explicit compatibility
gates until their native implementations are proven.

## Highlights

- Added a shared native memory-cache helper inside `fluxheim-server` for
  buffered HTTP/1 responses. Static-web cache and proxy cache now use the same
  entry metadata, TTL, age, pruning, response-header map, and cache-status
  helper code.
- Native HTTP/1 proxy routes can now attach a Fluxheim-owned memory cache for
  non-load-balanced upstreams when the cache policy is limited to the supported
  native subset.
- Native proxy cache lookup/fill now reuses the Pingora-independent
  `fluxheim-cache` request and response policy helpers for cache key
  construction, request bypasses, client revalidation, response
  `no-store`/`private`, `Set-Cookie`, status TTLs, content-type admission, and
  object-size limits.
- Native proxy cache emits configured cache status and reason headers. The
  live native listener test proves a cacheable proxy response returns `MISS`
  on first fill and `HIT` on the second request without contacting the origin.
- HEAD requests remain bypassed in the native proxy cache path so a HEAD probe
  cannot poison a cached GET body.
- Native root, vhost, and route readiness checks now accept only the supported
  memory-tier proxy cache subset and keep unsupported cache shapes blocked
  instead of silently dropping policy.
- Native HTTP/1 TLS startup now recognizes managed ACME certificate sources on
  `server.default_vhost`, so rustls deployments using `server.tls_listen` can
  start with a pending default-vhost ACME certificate source and serve HTTP-01
  issuance traffic instead of failing the TLS listener plan.
- Native proxy memory cache now bypasses shared-cache lookup/fill for requests
  carrying `Authorization`, keeps configured `BYPASS` cache-status headers on
  upstream error responses, and strips stored upstream `Age` so cache hits emit
  one recomputed `Age` header.
- Native proxy memory cache now isolates origin `Vary` response variants and
  configured `cache.vary_request_headers` variants in the native memory-cache
  key space.
- Native proxy memory cache now serves expired memory-cache entries under
  configured `stale_if_error_secs` when the single-upstream native proxy sees a
  matching upstream error or 5xx status.
- Native proxy memory cache now enforces `cache.origin_protection` fill budgets
  for the supported single-upstream memory-cache path.
- Native proxy memory cache now uses checked `Instant` arithmetic for freshness
  and stale-if-error expiry, bypassing cache admission instead of panicking if a
  constrained platform cannot represent the configured window.
- Native proxy memory cache now serves bounded single `Range` requests from
  fresh cached full objects, emits cached `416` responses for unsatisfiable
  ranges, and bypasses cache fill on range misses so upstream `206` responses
  are never stored under full-object keys.
- Native proxy memory cache now supports native load-balanced upstream pools;
  cache hits return before backend selection, and cache misses fill from the
  selected backend.

## Compatibility Notes

- Supported in this checkpoint: memory-tier proxy cache for ordinary GET
  responses from static or native load-balanced upstream pools, with optional
  cache-status headers, Vary/request-header variant isolation,
  `stale_if_error_secs` serving, and `cache.origin_protection` fill budgets. If
  `cache.range.enabled = true`, bounded single `Range` requests can be served
  from fresh cached full objects.
- Still blocked for native runtime readiness: disk/tiered proxy cache,
  slice composition, stale-while-revalidate, peer-fill, cache predictor, and
  policies outside the supported native memory-cache subset.
- The compatibility runtime remains available for unsupported cache policies
  until the remaining native cache parity gates are implemented and tested.

## Verification

- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_in_memory --locked`
- `cargo test -p fluxheim-server native_route_proxy_ --locked`
- `cargo test -p fluxheim-server --features acme,tls-rustls-backend native_http1_proxy_runtime_accepts_default_vhost_acme_certificate_source --locked`
- `cargo test -p fluxheim-server native_route_proxy_accepts_ --locked`
- `cargo test -p fluxheim-server native_http1_plan --locked`
- `cargo check -p fluxheim-server --all-features --locked`
