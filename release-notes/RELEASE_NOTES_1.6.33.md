# Fluxheim 1.6.33 Release Notes

Fluxheim 1.6.33 is the native proxy-cache parity release in the Pingora
removal line.

This first checkpoint adds Fluxheim-owned native memory-cache support for
ordinary HTTP/1 proxy responses. Disk cache, range/slice cache, Vary variants,
stale serving, peer-fill, predictor/origin-protection, and load-balanced proxy
cache remain explicit compatibility gates until their native implementations
are proven.

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

## Compatibility Notes

- Supported in this checkpoint: memory-tier proxy cache for ordinary GET
  responses from a single static upstream, with optional cache-status headers.
- Still blocked for native runtime readiness: disk/tiered proxy cache,
  range/slice responses, Vary isolation, stale-if-error,
  stale-while-revalidate, peer-fill, cache predictor/origin protection, and
  cache over native load-balanced upstream pools.
- The compatibility runtime remains available for unsupported cache policies
  until the remaining native cache parity gates are implemented and tested.

## Verification

- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_in_memory --locked`
- `cargo test -p fluxheim-server native_route_proxy_accepts_ --locked`
- `cargo test -p fluxheim-server native_http1_plan --locked`
- `cargo check -p fluxheim-server --all-features --locked`
