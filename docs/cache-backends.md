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
- Pingora cache locks collapse concurrent misses for the same cache key.
  `cache.lock`, `vhosts.cache.lock`, and `vhosts.routes.cache.lock` configure
  whether request collapsing is enabled and how long writer age and reader wait
  timeouts last. Defaults preserve the original 30 second writer age timeout
  and 30 second waiter timeout.
- `cache.status_header`, `vhosts.cache.status_header`, and
  `vhosts.routes.cache.status_header` optionally emit a cache debug header such
  as `X-Cache-Status: HIT`, `MISS`, `STALE`, `BYPASS`, `EXPIRED`, or
  `REVALIDATED` for requests that participate in the proxy cache.
- `cache.hide_response_headers`, `vhosts.cache.hide_response_headers`, and
  `vhosts.routes.cache.hide_response_headers` remove explicitly configured
  upstream response headers before cache admission and downstream delivery.
  This is intended for tightly scoped static-asset routes where operators know
  a header such as `Set-Cookie` is not part of the cache identity.
- `cache.bypass_request_headers`, `vhosts.cache.bypass_request_headers`, and
  `vhosts.routes.cache.bypass_request_headers` bypass cache lookup and storage
  when any listed request header is present. Use this for route policies where
  headers such as `Cookie` or `Authorization` make the upstream response
  request-specific.
- `cache.vary_request_headers`, `vhosts.cache.vary_request_headers`, and
  `vhosts.routes.cache.vary_request_headers` add safe request headers to the
  Pingora cache variance key even when the origin does not emit a matching
  `Vary` header. Sensitive headers such as `Cookie`, `Authorization`, and
  `Proxy-Authorization` are rejected here; use `bypass_request_headers` for
  request-specific responses.
- `cache.key_namespace`, `vhosts.cache.key_namespace`, and
  `vhosts.routes.cache.key_namespace` add an operator-controlled namespace
  component to the primary cache key. Bump this value to isolate new objects
  from older route-cache contents without changing URLs.
- `cache.key_parts`, `vhosts.cache.key_parts`, and
  `vhosts.routes.cache.key_parts` provide a constrained cache-key template made
  from safe request fields: `method`, `host`, `path`, and `query`. `path` is
  required, duplicates are rejected, and `query` still obeys `include_query`.
- `cache.ignore_origin_cache_headers`,
  `vhosts.cache.ignore_origin_cache_headers`, and
  `vhosts.routes.cache.ignore_origin_cache_headers` remove upstream
  `Cache-Control` and `Expires` before cache admission and downstream delivery.
  Keep this disabled except on tightly scoped static-asset routes where
  Fluxheim's cache policy owns freshness.
- `cache.status_ttls`, `vhosts.cache.status_ttls`, and
  `vhosts.routes.cache.status_ttls` define explicit positive TTLs by response
  status. Matching cache-participating origin responses have their freshness
  headers normalized to `Cache-Control: public, max-age=<ttl>` before cache
  admission. Non-200 statuses are only admitted when explicitly listed here.
- `cache.stale_if_error_secs`, `vhosts.cache.stale_if_error_secs`, and
  `vhosts.routes.cache.stale_if_error_secs` add an explicit stale-if-error
  window to cache-participating responses. Pingora can then serve an expired
  stored object during upstream errors while the stale window is still valid.
- `cache.stale_if_error_on`, `vhosts.cache.stale_if_error_on`, and
  `vhosts.routes.cache.stale_if_error_on` can narrow that behavior to selected
  upstream error classes such as `connect`, `timeout`, `read`, `write`,
  `connection-closed`, `http-status`, `protocol`, `tls`, and `other`. The
  default includes all classes for compatibility with the stale-if-error
  window.
- `cache.stale_if_error_statuses`, `vhosts.cache.stale_if_error_statuses`, and
  `vhosts.routes.cache.stale_if_error_statuses` can narrow HTTP-status
  stale-if-error serving to selected 5xx origin statuses. An empty list means
  all upstream 5xx statuses that Pingora marks stale-if-error eligible.
- `cache.stale_while_revalidate_secs`,
  `vhosts.cache.stale_while_revalidate_secs`, and
  `vhosts.routes.cache.stale_while_revalidate_secs` add an explicit
  stale-while-revalidate window to cache-participating responses. Pingora can
  then serve an expired stored object while revalidating it with the upstream.
- `cache.content_types`, `vhosts.cache.content_types`, and
  `vhosts.routes.cache.content_types` allow exact media types and subtype
  wildcards such as `image/*`. The `extensions` key is accepted as the
  user-facing alias for the request-path extension allow-list, while
  `image_extensions` remains accepted for older configs.
- `cache.include_query`, `vhosts.cache.include_query`, and
  `vhosts.routes.cache.include_query` control whether the request query string
  participates in the cache key. The default is `true`; disabling it should be
  limited to static routes where the query string is not part of origin
  response identity.
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
  admitted into the shared static cache. Origin `200 OK` responses must match
  the selected cache policy `content_types`, unless the selected cache policy
  explicitly defines a positive TTL for their non-200 status. Missing or
  disallowed `Content-Type` values still reject `200 OK` responses, and
  redirects or error statuses without an explicit TTL are rejected from shared
  cache admission.
  Pingora's cache
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
  stores, disk evictions, and purges. Activity blocks include derived
  `requests`, `hit_ratio_per_mille`, `miss_ratio_per_mille`,
  `store_attempts`, `store_ratio_per_mille`, `store_refusal_ratio_per_mille`,
  and `eviction_ratio_per_mille` fields so operators can read hit-rate,
  miss-rate, admission health, and eviction pressure without external JSON
  post-processing. Totals and per-vhost status include `configured_routes`,
  `routes_total`, `cache_route_coverage_ratio_per_mille`, `enabled_routes`,
  `enabled_route_ratio_per_mille`, `tiered_routes`, and
  `tiered_route_ratio_per_mille` so route-cache coverage is visible without
  parsing the route list. `routes_total` counts routes with explicit cache
  policy, while `configured_routes` counts all configured routes on the vhost.
  Per-vhost and per-route status also include `storage_tiers` so dashboards can
  distinguish memory-only, disk-only, and tiered caches without inspecting
  nested tier objects. Totals also include enabled and tiered vhost ratios.
  `POST /_fluxheim/cache/activity/reset` returns the same vhost and route
  coverage counters alongside the reset tier counts, so operational scripts can
  log cache coverage at the same time they clear activity counters.
  Memory and disk tier status also reports `memory_tiers`, `disk_tiers`,
  average object-size fields, `fill_ratio_per_mille`,
  `purge_index_entries`, `purge_index_max_entries`, and
  `purge_index_fill_ratio_per_mille`, and totals report the same values split
  by memory and disk tiers, so operators can tell whether storage is under
  pressure, whether object-size budgets are realistic, and whether indexed
  scope, prefix, and wildcard purges have useful coverage or are near the
  bounded index cap.
  `POST /_fluxheim/cache/activity/reset` resets vhost and route activity
  counters without clearing cached objects.
- `cache.status_header` can expose compact response debug states such as
  `HIT`, `MISS`, `STALE`, and `BYPASS`. `cache.status_reason_header` can expose
  bounded no-cache reasons such as `OriginNotCache`, `ResponseTooLarge`, or
  Fluxheim policy reasons such as `cache-min-uses`. Keep the reason header
  disabled unless actively debugging a cache policy.
  `POST /_fluxheim/cache/purge` invalidates one cache identity from the
  selected vhost or, when `route` / `x-fluxheim-cache-route` is provided, from
  the selected route cache. If the object has negotiated `Vary` variants,
  memory and disk purge remove every stored variant for that primary identity.
  Purge responses echo the cache `scope` (`vhost` or `route`), normalized host,
  method, path, and optional query for each requested identity so operators can
  audit purges without decoding cache keys. Single purge responses and each
  bulk result include `not_purged`, `memory_not_purged`, and `disk_not_purged`
  booleans alongside the corresponding purged booleans.
  `POST /_fluxheim/cache/purge-bulk` invalidates multiple identities that share
  the same host, method, vhost, optional route, and optional original URL query.
  Bulk purge responses echo the cache `scope` and optional `route`, and include
  `not_purged`, `purged_ratio_per_mille`, and
  `not_purged_ratio_per_mille` so operators can see how much of the requested
  batch missed or matched existing cache entries. They also include
  `memory_purged`, `memory_not_purged`, `memory_purged_ratio_per_mille`,
  `memory_not_purged_ratio_per_mille`, `disk_purged`, `disk_not_purged`,
  `disk_purged_ratio_per_mille`, and `disk_not_purged_ratio_per_mille` so
  tier-specific cleanup is visible without parsing each result.
  Purge identities are bounded before key derivation: hosts, methods, paths,
  queries, and bulk path count have explicit limits; paths must start with `/`;
  path traversal segments, encoded path separators, encoded dots, backslashes,
  control bytes, and malformed host/method/query values are rejected.
  `POST /_fluxheim/cache/purge-index` invalidates entries from the bounded cache
  index for a whole vhost cache, or for a route cache when `route` /
  `x-fluxheim-cache-route` is provided. This is the intended operator command
  for full-scope vhost or route invalidation without constructing individual
  cache keys.
  `POST /_fluxheim/cache/purge-prefix` invalidates indexed entries for a vhost
  or route whose normalized request path starts with `path_prefix` / `prefix` /
  `x-fluxheim-cache-path-prefix`. Prefix purge requires a non-root prefix such
  as `/assets/`; `/` is rejected so complete cache clears stay explicit through
  scope purge. `POST /_fluxheim/cache/purge-wildcard` invalidates indexed
  entries by absolute path pattern using `*`, for example `/assets/*.png`.
  Whole-cache patterns such as `/*` are rejected for the same reason. Indexed
  endpoints accept `limit` /
  `x-fluxheim-cache-limit`, default to a bounded batch size, and return
  the effective `limit`, cache `scope`, and `purged_ratio_per_mille` in their
  response. The ratio reports how much of the matched batch was actually
  purged, where `1000` means every matched entry was removed. Indexed purge
  responses also include `not_purged`, `not_purged_ratio_per_mille`,
  `memory_not_purged`, `memory_not_purged_ratio_per_mille`,
  `disk_not_purged`, `disk_not_purged_ratio_per_mille`,
  `memory_purged_ratio_per_mille`, and `disk_purged_ratio_per_mille` so
  operators can see which tier needs cleanup.
  They return
  `truncated = true` and `repeat_required = true` when more indexed entries
  remain for the requested scope and the same purge should be run again. The
  index is bounded in memory, mirrors disk-tier writes, and is designed for
  operational invalidation rather than as a complete filesystem scan.
  A background disk purger remains planned.

Example admin cache invalidation requests:

```sh
curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-index?vhost=repoheim.eu&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-prefix?vhost=repoheim.eu&path_prefix=/assets/&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-wildcard?vhost=repoheim.eu&pattern=/assets/*.png&limit=500"
```

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
  invalidation, including vhost and route-scoped cache policies.
- Expose operator cache counters. Implemented through the protected
  `GET /_fluxheim/cache/status` admin endpoint.
- Have focused tests for hit, miss, oversized object, purge, and vhost key
  isolation behavior.
