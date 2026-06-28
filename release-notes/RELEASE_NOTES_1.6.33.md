# Fluxheim 1.6.33 Release Notes

Fluxheim 1.6.33 is the native proxy-cache parity release in the Pingora
removal line.

This checkpoint adds Fluxheim-owned native memory-cache and filesystem disk
cache support for ordinary HTTP/1 proxy responses. Encrypted disk and
storage-bin disk remain explicit compatibility gates until their native
implementations are proven.

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
- Native proxy memory cache now supports `cache.min_uses`,
  `cache.pass_uncacheable_after`, and opt-in `[cache.predictor]` cache-pass
  decisions with bounded Fluxheim-owned counters. Cacheable responses clear
  cache-pass state before min-use admission, matching the existing
  compatibility behavior.
- Native proxy memory cache now supports `stale_while_revalidate_secs` for
  expired memory objects. The native path serves a `STALE-UPDATING` response,
  keeps origin-fill protection in front of the refresh task, and updates the
  cached object through the same response admission path.
- Native proxy memory cache now supports `[cache.lock]` request collapsing for
  concurrent same-key memory-cache misses. The first request fills from origin;
  matching readers wait up to `wait_timeout_secs` and then serve the completed
  object as a normal `HIT` when the fill succeeds.
- Native proxy memory cache now supports memory-tier `[cache.range.slice]`
  composition. The native path fetches fixed-size origin slices with bounded
  `Range` subrequests, validates `206`, `Content-Range`, `Content-Length`,
  identity encoding, and matching ETag/Last-Modified identity, then composes
  single-range or multipart responses from cached slices.
- Native proxy memory cache now supports peer-fill over HTTPS and over
  constrained HTTP peers. HTTPS peers use the native upstream TLS connector and
  derive SNI from the peer URL host; plaintext HTTP peers are accepted only for
  loopback peers or when `cache.peer_fill.allow_insecure_http = true`. Native
  peer-fill preserves the `X-Fluxheim-Peer-Fill` loop guard, sends
  `Cache-Control: only-if-cached`, honors peer-fill concurrency limits, stores
  successful peer `200` responses locally, and returns `PEER-HIT` before later
  requests become normal memory-cache `HIT`s.
- Native proxy cache now supports unencrypted filesystem disk cache and
  memory+disk tiering. Disk objects use hashed paths under the configured cache
  root, reuse the shared Fluxheim disk object envelope, persist freshness and
  stale windows as absolute timestamps, rebuild a bounded native index at
  startup, and promote fresh disk hits back into memory when the memory tier is
  enabled.
- Native peer-fill admission now subtracts upstream `Age` from peer response
  freshness, so aged peer objects cannot extend origin freshness when copied
  into local memory cache.
- Native cache-only requests with `Cache-Control: only-if-cached` now return a
  bounded `504` miss instead of contacting origin. A client-supplied
  `X-Fluxheim-Peer-Fill` marker alone no longer suppresses peer-fill.
- Hardened native cache internals by using checked static-web cache expiry
  arithmetic, suppressing duplicate stale-while-revalidate refresh tasks per
  cache key before task allocation, and avoiding full predictor-counter table
  scans on the hot miss path.

## Compatibility Notes

- Supported in this checkpoint: memory-tier proxy cache for ordinary GET
  responses from static or native load-balanced upstream pools, with optional
  cache-status headers, Vary/request-header variant isolation,
  `stale_if_error_secs` serving, `cache.origin_protection` fill budgets,
  native load-balanced pools, `cache.min_uses`, `pass_uncacheable_after`,
  opt-in `[cache.predictor]` cache-pass decisions,
  `stale_while_revalidate_secs` background refresh, `[cache.lock]` same-key
  request collapsing, memory-tier `[cache.range.slice]` composition,
  unencrypted filesystem disk cache, memory+filesystem-disk tiering, and
  HTTPS/loopback-or-opt-in HTTP peer-fill. If `cache.range.enabled = true`,
  bounded single `Range` requests can be served from fresh cached full objects
  or from compatible fixed-size memory slices when slice caching is enabled.
- Still blocked for native runtime readiness: encrypted disk cache,
  storage-bin disk cache, and policies outside the supported native proxy-cache
  subset.
- Security note: native HTTP peer-fill is intentionally available only when
  the peer is loopback or `allow_insecure_http = true`. Plaintext HTTP has no
  transport integrity and can be cache-poisoned by a network-path attacker; use
  HTTPS peers, loopback peers, encrypted overlays, mTLS sidecars, or trusted
  private networks.
- The compatibility runtime remains available for unsupported cache policies
  until the remaining native cache parity gates are implemented and tested.

## Verification

- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_in_memory --locked`
- `cargo test -p fluxheim-server native_route_proxy_min_uses_delays_memory_cache_admission --locked`
- `cargo test -p fluxheim-server native_route_proxy_predictor_passes_repeated_uncacheable_memory_response --locked`
- `cargo test -p fluxheim-server native_route_proxy_serves_stale_while_revalidating_memory_cache --locked`
- `cargo test -p fluxheim-server native_route_proxy_cache_lock_collapses_concurrent_memory_fills --locked`
- `cargo test -p fluxheim-server native_route_proxy_slice_cache_fills_and_composes_memory_range --locked`
- `cargo test -p fluxheim-server native_route_proxy_slice_cache_composes_multipart_memory_response --locked`
- `cargo test -p fluxheim-server native_route_proxy_accepts_route_memory_proxy_cache_with_https_peer_fill --locked`
- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_on_disk --locked`
- `cargo test -p fluxheim-server native_route_proxy_tiered_cache_refills_memory_from_disk --locked`
- `cargo test -p fluxheim-server native_route_proxy_peer_fills_and_stores_memory_cache_response --locked`
- `cargo test -p fluxheim-server static_cache_expiry_rejects_unrepresentable_ttl --locked`
- `cargo test -p fluxheim-server native_route_proxy_ --locked`
- `cargo test -p fluxheim-server --features acme,tls-rustls-backend native_http1_proxy_runtime_accepts_default_vhost_acme_certificate_source --locked`
- `cargo test -p fluxheim-server native_route_proxy_accepts_ --locked`
- `cargo test -p fluxheim-server native_http1_plan --locked`
- `cargo check -p fluxheim-server --all-features --locked`
