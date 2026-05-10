# Cache Backends

Fluxheim's cache configuration is intentionally byte-budgeted even when a
backend crate is count-based. Operators should be able to say "use 1 GiB of RAM"
or "use this 10 GiB disk directory" globally or per vhost without knowing the
internal cache implementation.

## Current Implementation

- Global and per-vhost cache policies share the same typed model.
- `cache.memory.max_size_bytes` is converted into a conservative object-slot
  plan by dividing the memory budget by `cache.max_object_bytes`.
- Enabled memory tiers create a byte-weighted in-process `moka` cache per
  runtime vhost policy.
- `cache.disk.path` and `cache.disk.max_size_bytes` are retained in the storage
  plan after config-path resolution.
- Enabled tier budgets must be at least as large as `cache.max_object_bytes`.
- `cache.enabled = true` requires at least one storage tier.
- The proxy emits vhost-aware Pingora cache keys and enables Pingora `HttpCache`
  admission for eligible image requests with a configured memory or disk tier.
- Pingora cache locks collapse concurrent misses for the same cache key, with a
  30 second writer age timeout and 30 second waiter timeout.
- `cache.status_header`, `vhosts.cache.status_header`, and
  `vhosts.routes.cache.status_header` optionally emit a cache debug header such
  as `X-Cache-Status: HIT`, `MISS`, `STALE`, `BYPASS`, `EXPIRED`, or
  `REVALIDATED` for requests that participate in the proxy cache.
- The first Pingora memory adapter stores complete objects only; it buffers up to
  `cache.max_object_bytes` and refuses anything larger.
- The first Pingora disk adapter stores complete objects below `cache.disk.path`
  using SHA-256-derived shard paths, same-directory temporary files, and atomic
  rename. It refuses objects above `cache.max_object_bytes`, evicts the oldest
  `.fhc` files when needed to enforce `cache.disk.max_size_bytes`, and refuses
  admission only when the incoming object still cannot fit after eviction.
- Disk-cache reads canonicalize existing object paths, open cache objects
  without following symlinks on Linux, verify the opened handle is a regular
  file, and refuse encoded files larger than the configured object budget plus
  bounded metadata overhead. Disk-cache writes verify that shard directories
  still resolve under the canonical cache root before opening a no-follow
  same-directory temp file and renaming it into place. Symlinked cache roots,
  cache roots below symlinked parent directories, object files, write
  destinations, and shard escapes are refused. Eviction scans also use
  non-following metadata, ignore symlinked shards or objects, and fail closed
  when a scan exceeds 100000 cache objects so cache stats or eviction cannot
  allocate an unbounded entry list. Purge, invalid-object cleanup, and eviction
  re-check the target immediately before deletion and only remove regular
  `.fhc` cache objects. Shard directories and object files must be symlink-free,
  even when a symlink points back inside the cache root; mount or configure the
  real cache directory path.
- Partial-write streaming is explicitly disabled for the production memory
  and disk adapters until in-progress response buffering can be bounded for
  unknown-size origin responses.
- Cache-header semantics are partially implemented and remain a cache-pack
  hardening requirement before cache is considered complete. Static responses
  emit configurable `Cache-Control`, optional `Expires`, `ETag`,
  `Last-Modified` when available,
  `Accept-Ranges`, and range headers, and they honor `If-Match`,
  `If-Unmodified-Since`, `If-None-Match`, `If-Modified-Since`, request
  `Cache-Control`, `Pragma`, single `Range`, and `If-Range`. Header policy lets
  operators set, append, and unset
  browser/CDN-facing headers such as `Cache-Control`, `Expires`, `Vary`, and
  provider-specific cache controls. Proxied image cache admission currently
  bypasses Fluxheim's cache when the request sends `Cache-Control: no-cache`,
  `Cache-Control: no-store`, `Cache-Control: max-age=0`, or
  `Pragma: no-cache`. Proxied image cache admission also refuses shared-cache
  storage when origin responses send `Cache-Control: no-store`, `private`,
  `no-cache`, `max-age=0`, or `s-maxage=0`, because validator-based
  revalidation is not complete yet. Proxied cache variants use Pingora's
  variance hook for `Vary`; repeated `Vary` headers are normalized, request variant headers are
  hashed into the variant key, and unsafe or identity-sensitive `Vary` headers
  are rejected from cache admission. Responses carrying `Set-Cookie` are not
  admitted into the shared image cache. Origin responses must be successful
  `200 OK` image responses to enter the shared image cache: missing or
  non-image `Content-Type` values, redirects, and error statuses are rejected
  from shared image-cache admission. Pingora's cache
  pipeline injects `Age` on stored-response hits and applies downstream
  conditional/range handling when cache is enabled. Planned work covers
  end-to-end cached-hit verification for those Pingora behaviors, full
  validator-based revalidation for proxied cache responses, and broader
  cache-header tests for static and proxied responses.
- When both memory and disk tiers are enabled on a vhost, Fluxheim uses a
  tiered Pingora storage adapter: memory is L1, disk is L2, misses are written
  to both tiers, disk hits are promoted back into memory when they fit, and
  purge invalidates both tiers.
- The protected admin endpoint `GET /_fluxheim/cache/status` reports aggregate,
  per-vhost, and per-route cache enablement, tiering, memory counters, disk
  counters, and cache activity counters for hits, misses, stores, refused
  stores, and purges. `POST /_fluxheim/cache/activity/reset` resets vhost and
  route activity counters without clearing cached objects.
  `POST /_fluxheim/cache/purge` invalidates one cache identity from the
  selected vhost. If the object has negotiated `Vary` variants, memory and disk
  purge remove every stored variant for that primary identity. `POST
  /_fluxheim/cache/purge-bulk` invalidates multiple identities that share the
  same host, method, vhost, and optional original URL query.
  Purge identities are bounded before key derivation: hosts, methods, paths,
  queries, and bulk path count have explicit limits; paths must start with `/`;
  path traversal segments, encoded path separators, encoded dots, backslashes,
  control bytes, and malformed host/method/query values are rejected.
  Prefix and tag purge need a cache index and remain planned.

Example: `cache.memory.max_size_bytes = "1GiB"` with
`cache.max_object_bytes = "32MiB"` plans 32 in-memory object slots.

## Memory Cache Evaluation

Checked on 2026-05-04:

- `pingora-memory-cache` latest: `0.8.0`
- License: `Apache-2.0`
- Repository: `cloudflare/pingora`
- API shape: generic in-memory cache with stampede protection.
- Capacity model: item count.
- Pingora HTTP cache compatibility: not a drop-in backend for
  `pingora::cache::storage::Storage`.

Checked on 2026-05-05:

- `moka` latest: `0.12.15`
- License: `(MIT OR Apache-2.0) AND Apache-2.0`
- Rust version: `1.71.1`
- Capacity model: weighted capacity with a caller-provided weigher.
- Fluxheim use: current byte-weighted memory tier.

Checked on 2026-05-05:

- `sha2` latest: `0.11.0`
- License: `MIT OR Apache-2.0`
- Rust version: `1.85`
- Fluxheim use: fixed-length disk cache object paths.

Pingora's HTTP cache storage layer requires implementations of `Storage`,
`HandleHit`, and `HandleMiss`. Fluxheim now has memory, disk, and tiered
memory-plus-disk implementations of those traits. Request collapsing is
integrated with Pingora cache locks. The next adapter pass should design bounded
partial streaming writes instead of copying Pingora's test-only in-memory cache
behavior.

## Adapter Requirements

A production adapter must:

- Enforce byte budgets, not only item counts.
- Refuse objects larger than `cache.max_object_bytes`.
- Preserve HTTP cache metadata, including status, headers, validators, and
  freshness metadata.
- Implement full cache-header behavior for:
  `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Vary`, `Age`,
  `Accept-Ranges`, `If-None-Match`, `If-Modified-Since`, request
  `Cache-Control`, `Pragma`, `Range`, and `If-Range`.
- Implemented now: static validators/ranges/client refresh controls, proxied
  client refresh bypass, Pingora `Vary` variance keys with unsafe/sensitive
  `Vary` rejection, shared-cache refusal for `Set-Cookie` responses, and
  `image/*` origin response admission for proxied image cache.
- Keep CDN/browser cache headers configurable through header policy and
  examples instead of hardcoded provider-specific defaults.
- Avoid unbounded buffering for large responses. Implemented for memory by
  enforcing `cache.max_object_bytes` and keeping partial streaming disabled;
  bounded partial streaming is still pending.
- Support request collapsing or integrate with Pingora cache locks. Implemented
  for the memory tier.
- Expose purge semantics for the future admin API. Implemented in the storage
  adapters and protected admin endpoint for single-key and same-host bulk exact
  invalidation.
- Expose operator cache counters. Implemented through the protected
  `GET /_fluxheim/cache/status` admin endpoint.
- Have focused tests for hit, miss, oversized object, purge, and vhost key
  isolation behavior.
