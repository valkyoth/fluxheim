# Fluxheim 1.6.33 Release Notes

Fluxheim 1.6.33 is the native proxy-cache parity release in the Pingora
removal line.

This checkpoint adds Fluxheim-owned native memory-cache, filesystem and
storage-bin disk cache, local-key and OpenBao Transit encrypted disk cache, and
memory+disk tiering for ordinary HTTP/1 proxy responses.

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
- Native proxy cache now supports local-key encrypted filesystem disk cache.
  The native path reuses the existing `FLUXHEIM-CACHE-ENC-v1` AES-256-GCM
  envelope, loads the same safe `key_file`/`key_credential` sources, rejects
  plaintext objects while encryption is enabled, and has live listener coverage
  proving encrypted disk `MISS` then `HIT` reuse without storing the origin
  response body in plaintext on disk.
- Native proxy cache now supports the `storage-bin` disk backend. The native
  path prepares the same manifest/bin layout, persists a bounded native index,
  rebuilds free-space state at startup, evicts oldest objects when the storage
  budget is full, and has live listener coverage proving storage-bin `MISS`
  then `HIT` reuse across a native proxy restart.
- Native proxy cache now supports local-key encrypted storage-bin disk cache.
  The same encrypted disk-object envelope is written into bin slots, and live
  listener coverage proves restart `HIT` reuse without storing the origin
  response body in plaintext inside bin files.
- Native proxy cache now supports OpenBao Transit encrypted disk cache in the
  native cache path. The native adapter reuses the existing
  `FLUXHEIM-CACHE-ENC-v1` envelope, sends Transit `encrypt`/`decrypt` requests
  with authenticated cache-key data, disables OpenBao redirects, caps Transit
  response bodies, trims zeroized token-file/credential secrets before header
  use, and has live storage-bin listener coverage proving `MISS`, restart
  validation decrypt, and `HIT` decrypt behavior.
- Native peer-fill admission now subtracts upstream `Age` from peer response
  freshness, so aged peer objects cannot extend origin freshness when copied
  into local memory cache.
- Native cache-only requests with `Cache-Control: only-if-cached` now return a
  bounded `504` miss instead of contacting origin. A client-supplied
  `X-Fluxheim-Peer-Fill` marker is stripped before normal proxy handling and
  no longer suppresses peer-fill.
- Hardened native cache internals by using checked static-web cache expiry
  arithmetic, suppressing duplicate stale-while-revalidate refresh tasks per
  cache key before task allocation, and avoiding full predictor-counter table
  scans on the hot miss path.
- Hardened native cache admin purge parity by adding a Fluxheim-owned native
  memory-cache purge index and wiring exact, bulk, prefix, tag, wildcard,
  route-scope, and stale purge operations through live native memory state as
  well as disk state. The proxy-cache smoke now proves those purges cannot
  leave a native memory `HIT` or `STALE` response behind while the origin is
  stopped.
- Closed native observability parity gaps found during the final release gate:
  native HTTP/1 proxy requests now regenerate forwarded `traceparent` span IDs,
  record proxy request counters, expose native cache memory/disk runtime gauges,
  and publish native cache lookup duration histograms through the existing
  Prometheus metrics surface.
- Fixed native disk-cache purge parity so exact, bulk, prefix, tag, wildcard,
  route-scope, stale, and slice path-exact purges operate on the live native
  filesystem/storage-bin disk cache instead of a reconstructed throwaway cache.
  Native disk cache now keeps its own purge index and reports non-zero disk
  purge-index metrics when indexed disk objects are present.
- Moved native disk-cache lookup and store work onto Tokio's blocking pool.
  This covers filesystem I/O, storage-bin I/O, storage-bin index persistence,
  and OpenBao Transit encrypt/decrypt HTTP calls so cache operations do not
  pin async worker threads while external storage or OpenBao is slow.
- Reduced storage-bin write amplification by batching index persistence for
  multi-object eviction during one cache store, instead of rewriting the full
  storage-bin index after every single evicted object.
- Hardened native cache encryption and rebuild behavior by bounding
  filesystem cache-object reads before startup rebuild parsing, zeroizing
  transient decrypted OpenBao/native serialized-object buffers, and logging
  local AES-GCM key-rotation warnings as a process approaches the random-nonce
  invocation bound.
- Native filesystem disk-cache startup scans now list root and shard
  directories through the native safe disk-cache path wrapper, keeping the
  symlink/canonical path boundary explicit at the directory traversal point.
- Native disk-cache indexed purge removals now update object state and purge
  index membership under the same cache-state lock, closing a split-lock race
  where a concurrent store could become invisible to indexed purge operations.
- Updated `arc-swap` to 1.9.2 and `env_logger` to 0.11.11.
- Stale admin purges now log an explicit security warning if the system clock
  regresses before the Unix epoch, instead of silently substituting timestamp
  zero without operator visibility.

## Compatibility Notes

- Supported in this checkpoint: memory-tier proxy cache for ordinary GET
  responses from static or native load-balanced upstream pools, with optional
  cache-status headers, Vary/request-header variant isolation,
  `stale_if_error_secs` serving, `cache.origin_protection` fill budgets,
  native load-balanced pools, `cache.min_uses`, `pass_uncacheable_after`,
  opt-in `[cache.predictor]` cache-pass decisions,
  `stale_while_revalidate_secs` background refresh, `[cache.lock]` same-key
  request collapsing, memory-tier `[cache.range.slice]` composition,
  unencrypted, local-key encrypted, or OpenBao Transit encrypted filesystem or
  storage-bin disk cache, memory+disk tiering, and HTTPS/loopback-or-opt-in
  HTTP peer-fill.
  If `cache.range.enabled = true`, bounded single `Range` requests can be
  served from fresh cached full objects or from compatible fixed-size memory
  slices when slice caching is enabled.
- Native runtime readiness still rejects cache policies that are attached to no
  native cacheable handler or whose route/upstream shape is outside the
  supported native proxy-cache subset; it no longer has a backend/encryption
  parity gate for filesystem, storage-bin, local-key, or OpenBao Transit disk
  cache.
- Security note: native HTTP peer-fill is intentionally available only when
  the peer is loopback or `allow_insecure_http = true`. Plaintext HTTP has no
  transport integrity and can be cache-poisoned by a network-path attacker; use
  HTTPS peers, loopback peers, encrypted overlays, mTLS sidecars, or trusted
  private networks.
- The compatibility runtime remains available for unsupported cache policy
  shapes while operators migrate route layouts to the native-supported subset.

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
- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_on_encrypted_disk --locked`
- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_on_storage_bin_disk --locked`
- `cargo test -p fluxheim-server native_route_proxy_caches_proxy_response_on_encrypted_storage_bin_disk --locked`
- `cargo test -p fluxheim-server --features openbao-cache-encryption native_route_proxy_caches_proxy_response_on_openbao_storage_bin_disk --locked`
- `cargo test -p fluxheim-server native_route_proxy_tiered_cache_refills_memory_from_disk --locked`
- `cargo test -p fluxheim-server native_route_proxy_peer_fills_and_stores_memory_cache_response --locked`
- `cargo test -p fluxheim-server native_storage_bin_disk_purge_uses_live_cache_instance --locked`
- `cargo test -p fluxheim-server static_cache_expiry_rejects_unrepresentable_ttl --locked`
- `cargo test -p fluxheim-server native_route_proxy_regenerates_forwarded_traceparent_span_id --features otel-tracing --locked`
- `cargo test -p fluxheim-server --features acme,tls-rustls-backend native_http1_proxy_runtime_accepts_default_vhost_acme_certificate_source --locked`
- `cargo test -p fluxheim-server native_http1_plan --locked`
- `cargo check -p fluxheim-server --all-features --locked`
- `cargo check -p fluxheim --features profile-observability --locked`
- `sh scripts/smoke_observability_local.sh`
- `sh scripts/smoke_proxy_cache.sh`
- `scripts/podman_smoke.sh`
- `scripts/stable_release_gate.sh check`
