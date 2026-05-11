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
- The disk tier currently stores one object per filesystem-managed cache file.
  This keeps the implementation portable, inspectable, and easy to recover. A
  future advanced backend may add slab/bin storage with pre-allocated data
  files to reduce filesystem overhead and fragmentation on very large,
  high-churn caches.
- Enabled tier budgets must be at least as large as `cache.max_object_bytes`.
- `cache.enabled = true` requires at least one storage tier.
- The proxy emits vhost-aware Pingora cache keys and enables Pingora `HttpCache`
  admission for eligible image requests with a configured memory or disk tier.
- Pingora cache locks collapse concurrent misses for the same cache key to
  prevent cache stampedes when many clients request the same uncached or
  expired object at once. One request receives the writer permit and fetches
  from the origin; matching readers wait for that writer up to the configured
  timeout instead of all hitting the origin together. `cache.lock`,
  `vhosts.cache.lock`, and `vhosts.routes.cache.lock` configure whether request
  collapsing is enabled and how long writer age and reader wait timeouts last.
  Defaults preserve the original 30 second writer age timeout and 30 second
  waiter timeout.
- `cache.status_header`, `vhosts.cache.status_header`, and
  `vhosts.routes.cache.status_header` optionally emit a cache debug header such
  as `X-Cache-Status: HIT`, `MISS`, `STALE`, `BYPASS`, `EXPIRED`, or
  `REVALIDATED` for requests that participate in the proxy cache.
- `cache.hide_response_headers`, `vhosts.cache.hide_response_headers`, and
  `vhosts.routes.cache.hide_response_headers` remove explicitly configured
  upstream response headers before cache admission and downstream delivery.
  This is intended for tightly scoped static-asset routes where operators know
  a header such as `Set-Cookie` is not part of the cache identity.
- `cache.tag_headers`, `vhosts.cache.tag_headers`, and
  `vhosts.routes.cache.tag_headers` control which origin response headers are
  trusted as cache-tag sources for indexed tag purge. Defaults are
  `Surrogate-Key`, `Cache-Tag`, and `X-Cache-Tags`; set an empty list to
  disable tag indexing for a cache policy.
- `cache.bypass_request_headers`, `vhosts.cache.bypass_request_headers`, and
  `vhosts.routes.cache.bypass_request_headers` bypass cache lookup and storage
  when any listed request header is present. Use this for route policies where
  headers such as `Cookie` or `Authorization` make the upstream response
  request-specific.
- `bypass_request_header_values`, `bypass_cookie_names`,
  `bypass_cookie_values`, `bypass_query_params`, and `bypass_query_values`
  provide narrower bypass controls for preview flags, session cookies, and
  private query modes while keeping unrelated public requests cacheable.
- `status_ttls` allows deliberate negative caching for configured statuses,
  such as a bounded 404 TTL for immutable asset paths.
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
- `cache.pass_uncacheable_after`, `vhosts.cache.pass_uncacheable_after`, and
  `vhosts.routes.cache.pass_uncacheable_after` can temporarily pass repeated
  uncacheable cache keys around cache lookup and storage. The feature is
  disabled by default and uses a bounded, short-lived in-memory table so dynamic
  one-off responses do not turn into unbounded state.
- `fluxheim cache-warm` preloads explicit paths through a running local
  Fluxheim HTTP listener. It uses normal `GET` requests with the selected Host
  header, so vhost routing, route matching, cache keys, and admission rules are
  identical to real traffic. It accepts repeated `--path` values or an input
  file containing `/path` or `host.example /path` lines. Input files are capped
  at 1 MiB, and the parsed target count is still bounded by `--max-targets`.
  Warm requests count 2xx and 3xx responses as successful by default. Use
  repeated `--allow-status` values only for deliberate negative-cache
  workflows, such as warming a configured 404 TTL. When a cache policy emits a
  status header,
  `--expect-cache-status` can require bounded values such as `MISS`, `HIT`, or
  `REVALIDATED`, so release scripts can fail if a warm request bypassed the
  cache unexpectedly. Use `--repeat` with `--expect-cache-status-sequence` to
  verify an expected transition, such as first-fill `MISS` followed by `HIT`.
  The proxy cache smoke suite verifies path warming, input-file dry-run
  validation, input-file warming, negotiated variant warming, and a deliberate
  404 negative-cache warm using `--allow-status 404`. The same smoke path
  asserts Prometheus cache activity counters for disk hits and scoped purge
  events, policy bypasses, and allowed stale serving.
  Use repeated `--header "Name: value"` options to warm negotiated variants for
  safe request headers such as `Accept-Language` or `Accept-Encoding`; use
  `--host` for the Host header. Use `--dry-run` to validate the target list,
  repeat count, listener selection, request headers, and expected cache-status
  sequence without sending requests to the running server.
  The command prints bounded summary counts for response statuses, observed
  cache-status values, and failure reasons so release jobs can distinguish
  upstream errors, unexpected response statuses, and unexpected cache behavior
  without parsing every per-target line.
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
  rename. It refuses objects above `cache.max_object_bytes`, maintains a
  runtime disk-object index for stats and least-recently-used eviction, and
  refuses admission only when the incoming object still cannot fit after
  eviction.
- Disk-cache reads canonicalize existing object paths, open cache objects
  without following symlinks on Linux, verify the opened handle is a regular
  file, and refuse encoded files larger than the configured object budget plus
  bounded metadata overhead. Disk-cache writes verify that shard directories
  still resolve under the canonical cache root before opening a no-follow
  same-directory temp file and renaming it into place. Symlinked cache roots,
  cache roots below symlinked parent directories, object files, write
  destinations, and shard escapes are refused. Startup scans walk the
  deterministic `00` through `ff` shard set instead of enumerating arbitrary
  cache-root children, ignore symlinked shards or objects, and fail closed when
  a scan exceeds 100000 cache objects so index rebuild cannot allocate an
  unbounded entry list. Runtime stats and eviction use the maintained
  disk-object index instead of repeated filesystem scans. Purge, invalid-object
  cleanup, and eviction re-check the target immediately before deletion and
  only remove regular `.fhc` cache objects. Shard directories and object files
  must be symlink-free, even when a symlink points back inside the cache root;
  mount or configure the real cache directory path. Startup removes stale
  Fluxheim-owned disk-cache temp files from the root temp directory and
  deterministic shard temp locations after a conservative age threshold, while
  ignoring unrelated files and fresh temp files so snapshot reloads do not race
  active cache writers.
- New disk cache objects use the v5 object header, which stores the combined
  cache key, primary key, user tag, cache tags, and path-index metadata. On
  startup Fluxheim first tries the root-local `.fluxheim-disk-index-v1`
  checkpoint. A valid checkpoint seeds the runtime disk-object index without a
  shard scan; a missing, corrupt, or stale checkpoint falls back to the
  deterministic shard scan and is rewritten. The rebuild path verifies each
  referenced cache object before indexing it, then rebuilds both the bounded
  purge index and the runtime disk-object index for v5 entries, so indexed
  scope, prefix, wildcard, tag, stale disk purges, stats, and eviction
  accounting survive process restarts. Older v1-v4 disk objects remain
  readable, but earlier formats cannot fully rebuild every indexed purge
  metadata field because they did not store all of the v5 index fields.
- Disk-only cache admission streams response chunks into a bounded temporary
  file under the cache root before the final atomic object write. Partial-write
  streaming remains disabled for the production memory and tiered adapters
  until in-progress object accounting is proven there as well.
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
  revalidation for zero-freshness admission is not complete yet. Proxied cache
  variants use Pingora's
  variance hook for `Vary`; repeated `Vary` headers are normalized, request variant headers are
  hashed into the variant key, and unsafe or identity-sensitive `Vary` headers
  are rejected from cache admission. Responses carrying `Set-Cookie` are not
  admitted into the shared static cache. Origin `200 OK` responses must match
  the selected cache policy `content_types`, unless the selected cache policy
  explicitly defines a positive TTL for their non-200 status. Missing or
  disallowed `Content-Type` values still reject `200 OK` responses, and
  redirects or error statuses without an explicit TTL are rejected from shared
  cache admission.
  Pingora's cache pipeline injects `Age` on stored-response hits and applies
  downstream conditional/range handling when cache is enabled. The release smoke
  suite verifies proxy cache HIT behavior, cached-hit `Age`, conditional `304`,
  byte-range `206`, `If-Range` match/mismatch behavior, cache-status HIT
  headers on cached conditional/range responses, validator-based upstream
  revalidation from an origin `304`, stale-object refresh from an origin `200`,
  stale-while-revalidate serving during a background refresh, stale-if-error
  serving after an upstream connection failure, cache-lock request collapsing
  for concurrent misses, `Vary` variant isolation, admin exact/bulk purge,
  stale dry-run, vhost prefix/tag/wildcard purge, and route-scoped purge against
  real cached objects, and disk-cache HIT behavior after a Fluxheim process
  restart without the origin available. The same smoke path asserts bounded
  Prometheus purge counters for exact, bulk, stale, prefix, tag, wildcard, and
  route-scoped index purge operations.
  HEAD requests intentionally bypass proxy cache storage with the bounded
  `method-head` reason; the smoke suite verifies those probes do not poison
  cached GET entries. Full HEAD-to-GET cache parity remains future
  compatibility work.
  Planned work still covers edge cases where origins change `Vary`, validators,
  or freshness headers during revalidation and broader cache-header matrix
  tests across static and proxied responses.
- When both memory and disk tiers are enabled on a vhost, Fluxheim uses a
  tiered Pingora storage adapter: memory is L1, disk is L2, misses are written
  to both tiers, disk hits are promoted back into memory when they fit, and
  purge invalidates both tiers.
- The protected admin endpoint `GET /_fluxheim/cache/status` reports aggregate,
  per-vhost, and per-route cache enablement, tiering, memory counters, disk
  counters, request-collapsing lock coverage, and cache activity counters for
  hits, misses, stores, refused stores, disk evictions, and purges. Activity
  blocks include derived
  `requests`, `hit_ratio_per_mille`, `miss_ratio_per_mille`,
  `store_attempts`, `store_ratio_per_mille`, `store_refusal_ratio_per_mille`,
  and `eviction_ratio_per_mille` fields so operators can read hit-rate,
  miss-rate, admission health, and eviction pressure without external JSON
  post-processing. Totals and per-vhost status include `configured_routes`,
  `routes_total`, `cache_route_coverage_ratio_per_mille`, `enabled_routes`,
  `enabled_route_ratio_per_mille`, `tiered_routes`,
  `tiered_route_ratio_per_mille`, `lock_enabled_policies`, and
  `lock_enabled_policy_ratio_per_mille` so route-cache and stampede-protection
  coverage are visible without parsing the route list. `routes_total` counts
  routes with explicit cache policy, while `configured_routes` counts all
  configured routes on the vhost.
  Per-vhost and per-route status also include `storage_tiers` and
  `lock_wait_timeout_secs` so dashboards can distinguish memory-only,
  disk-only, and tiered caches while also showing the configured request
  collapsing wait budget. Totals also include enabled and tiered vhost ratios.
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
  Prometheus `fluxheim_cache_activity_total{tier="policy",event="pass"}` and
  matching scoped counters record opt-in pass-cache bypass decisions without
  cache keys, hosts, or paths. Policy-level `bypass` records request-side
  cache bypass rules such as refresh controls, and policy-level `stale` records
  allowed stale serving decisions. Prometheus also exposes
  `fluxheim_cache_activity_scope_total{scope,vhost,route,tier,event}` for
configured vhost and route cache activity using only configured names and
bounded tier/event labels. `fluxheim_cache_lock_enabled_policies` reports
how many configured cache policies have request-collapsing locks enabled on a
real storage tier, so stampede-protection coverage is visible without cache
key or path labels. `fluxheim_cache_lock_wait_timeout_max_seconds` reports the
largest configured request-collapsing wait timeout across lock-enabled cache
policies, giving dashboards a low-cardinality timeout budget signal.
`fluxheim_cache_purges_total{operation,scope,vhost,route,mode}`
records successful admin purge commands with bounded operation and mode labels;
  it does not label cache keys, paths, tags, wildcard patterns, hosts, or query
  strings. When `[cache_purger]` is enabled,
  `fluxheim_cache_purger_runs_total{outcome}` and
  `fluxheim_cache_purger_entries_total{result}` expose bounded background stale
  disk cleanup progress, including `truncated` runs that need larger or more
  frequent cleanup windows.
  `POST /_fluxheim/cache/activity/reset` resets vhost and route activity
  counters without clearing cached objects.
- `cache.status_header` can expose compact response debug states such as
  `HIT`, `MISS`, `STALE`, and `BYPASS`. `cache.status_reason_header` can expose
  bounded no-cache reasons such as `OriginNotCache`, `ResponseTooLarge`, or
  Fluxheim policy reasons such as `request-refresh`, `request-header`,
  `request-header-value`, `request-cookie`, `request-query`, `cache-min-uses`,
  and `cache-pass`. The proxy cache smoke suite verifies these configured
  request-bypass reasons end to end. Keep the reason header disabled unless
  actively debugging a cache policy.
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
  scope purge. `POST /_fluxheim/cache/purge-tag` invalidates indexed entries
  for responses that carried one of the configured cache `tag_headers`.
  Tags are exact-match, bounded, de-duplicated per object, and may contain
  ASCII letters, digits, `_`, `-`, `.`, `:`, `/`, and `=`. Disk cache objects
  persist tags and path-index metadata in the v5 object format and rebuild the
  purge index across process restarts while continuing to read older object
  formats.
  Indexed scope, prefix, tag, and wildcard purge endpoints also accept
  `soft=true` or `x-fluxheim-cache-soft: true`. Soft purge rewrites only cache
  metadata so matched objects become stale immediately but keep their bodies on
  disk or in memory for revalidation and stale-serving policy. Hard purge is
  still the default.
  `POST /_fluxheim/cache/purge-stale` scans a bounded number of indexed
  entries for a vhost or route and removes objects whose stored freshness window
  has expired. It is intended as an operator-controlled incremental cleanup
  command and as the same bounded primitive used by the optional
  `[cache_purger]` background disk cleanup loop. Add `dry_run=true` or
  `x-fluxheim-cache-dry-run: true` to count stale objects without deleting
  them; dry-run responses include `would_purge` plus per-tier
  `memory_would_purge` and `disk_would_purge`. Stale purge also accepts
  `batches` / `x-fluxheim-cache-batches`. Each batch obeys the same bounded
  scan limit; dry-runs intentionally execute one scan, and responses set
  `increase_limit_required = true` when the scan was truncated but another
  identical batch would not make progress.
  `POST /_fluxheim/cache/purge-wildcard` invalidates indexed
  entries by absolute path pattern using `*`, for example `/assets/*.png`.
  Whole-cache patterns such as `/*` are rejected for the same reason. Indexed
  endpoints accept `limit` / `x-fluxheim-cache-limit` and `batches` /
  `x-fluxheim-cache-batches`, default to one bounded batch, and return the
  effective `limit`, executed `batches`, `batch_limit`, cache `scope`, and
  `purged_ratio_per_mille` in their response. The ratio reports how much of the
  matched batches was actually purged, where `1000` means every matched entry
  was removed. Indexed purge responses also include `not_purged`,
  `not_purged_ratio_per_mille`,
  `memory_not_purged`, `memory_not_purged_ratio_per_mille`,
  `disk_not_purged`, `disk_not_purged_ratio_per_mille`,
  `memory_purged_ratio_per_mille`, and `disk_purged_ratio_per_mille` so
  operators can see which tier needs cleanup.
  They return
  `truncated = true` and `repeat_required = true` when more indexed entries
  remain for the requested scope and the same purge should be run again.
  `batches_exhausted = true` means the configured batch limit was reached while
  more indexed entries may remain. The index is bounded in memory, mirrors
  disk-tier writes, and is designed for operational invalidation rather than as
  a complete filesystem scan.
  `[cache_purger]` can periodically run stale disk cleanup for every indexed
  vhost and route cache with conservative per-target `limit` and `batches`
  controls, while the admin endpoint remains available for explicit dry-runs
  and larger maintenance windows.

Example admin cache invalidation requests:

```sh
curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-index?vhost=repoheim.eu&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-prefix?vhost=repoheim.eu&path_prefix=/assets/&limit=500&batches=4"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-tag?vhost=repoheim.eu&cache_tag=release:2026-05-11&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-stale?vhost=repoheim.eu&limit=500&batches=4"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-stale?vhost=repoheim.eu&limit=500&dry_run=true"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-wildcard?vhost=repoheim.eu&pattern=/assets/*.png&limit=500"
```

Add `route=<route-name>` when the cache policy lives on a route instead of the
whole vhost:

```sh
curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-index?vhost=repoheim.eu&route=assets&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-prefix?vhost=repoheim.eu&route=assets&path_prefix=/assets/&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-tag?vhost=repoheim.eu&route=assets&cache_tag=release:2026-05-11&limit=500"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-stale?vhost=repoheim.eu&route=assets&limit=500&dry_run=true"

curl -X POST -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
  "http://127.0.0.1:9090/_fluxheim/cache/purge-wildcard?vhost=repoheim.eu&route=assets&pattern=/assets/*.png&limit=500"
```

The same route can be supplied through `x-fluxheim-cache-route` for automation
that keeps control parameters in headers instead of URLs.

Example cache warm after a release deploy:

```sh
fluxheim --config /etc/fluxheim/fluxheim.toml cache-warm \
  --listen 127.0.0.1:80 \
  --host repoheim.eu \
  --path /assets/css/index.css \
  --path /assets/img/logo.png

cat > /tmp/fluxheim-warm.txt <<'EOF'
repoheim.eu /assets/css/index.css
repoheim.eu /assets/img/logo.png
EOF

fluxheim --config /etc/fluxheim/fluxheim.toml cache-warm \
  --listen 127.0.0.1:80 \
  --input /tmp/fluxheim-warm.txt

fluxheim --config /etc/fluxheim/fluxheim.toml cache-warm \
  --listen 127.0.0.1:80 \
  --host repoheim.eu \
  --header "Accept-Language: de" \
  --path /assets/img/logo.png \
  --repeat 2 \
  --expect-cache-status-sequence MISS,HIT

fluxheim --config /etc/fluxheim/fluxheim.toml cache-warm \
  --listen 127.0.0.1:80 \
  --input /tmp/fluxheim-warm.txt \
  --header "Accept-Language: de" \
  --repeat 2 \
  --expect-cache-status-sequence MISS,HIT \
  --dry-run
```

Example cache-key preview during a production incident:

```sh
fluxheim --config /etc/fluxheim/fluxheim.toml cache-key \
  --host repoheim.eu \
  --header "Accept-Language: de" \
  --path /assets/img/logo.png \
  --query v=1 \
  --expect-eligible \
  --expect-cache-lock-enabled \
  --expect-memory-tier-enabled \
  --expect-disk-tier-enabled \
  --expect-scope vhost \
  --expect-vhost repoheim.eu \
  --expect-storage-tiers 2

fluxheim --config /etc/fluxheim/fluxheim.toml cache-key \
  --host repoheim.eu \
  --method HEAD \
  --path /assets/img/logo.png \
  --expect-ineligible \
  --expect-reason "method HEAD currently bypasses proxy cache storage"

fluxheim --config /etc/fluxheim/fluxheim.toml cache-lookup \
  --host repoheim.eu \
  --method HEAD \
  --path /assets/img/logo.png \
  --expect-ineligible \
  --expect-reason "method HEAD currently bypasses proxy cache storage" \
  --expect-objects 0

fluxheim --config /etc/fluxheim/fluxheim.toml cache-lookup \
  --host repoheim.eu \
  --header "Accept-Language: de" \
  --path /assets/img/logo.png \
  --query v=1 \
  --require-object \
  --expect-tier disk \
  --expect-status 200 \
  --expect-body-bytes 12345 \
  --expect-fresh-ttl-secs 120 \
  --expect-cache-tag asset:logo \
  --expect-header-name etag \
  --expect-header-name vary \
  --expect-cache-lock-enabled \
  --expect-memory-tier-enabled \
  --expect-disk-tier-enabled \
  --expect-scope vhost \
  --expect-vhost repoheim.eu \
  --expect-storage-tiers 2 \
  --expect-serve-stale-if-error \
  --expect-purge-indexed \
  --expect-freshness-state fresh
```

The preview and lookup commands validate the effective config, select the same
vhost and route cache policy as a live request, and print the selected
namespace, primary cache-key material, compact hashes, user tag, cache-lock
state, cache-lock wait timeout, selected memory/disk tier availability, and
ineligibility reason when the request is not admitted. `cache-lookup` also
checks the selected memory and disk tiers for matching objects and prints safe
metadata such as status, body size, freshness timestamps, cache tags, and stored
header names. It also reports a compact `freshness_state` plus
`serve_stale_while_revalidate` and `serve_stale_if_error` booleans, so incident
checks can distinguish a fresh object, an object still usable under stale
policy, and a fully expired object. `purge_indexed` tells whether indexed scope,
prefix, tag, wildcard, and stale purge operations can reach that object without
a full scan. It does not contact the upstream, read cached object bodies to
stdout, or dump stored header values. Use repeated `--header "Name: value"`
options to inspect negotiated cache variants that depend on safe request
headers such as `Accept-Language` or `Accept-Encoding`; use `--host` for the
Host header. For release scripts, `cache-lookup --require-object` fails when
the selected key has no cached object, repeated `--expect-tier memory|disk`
flags fail when no matching object is present in an allowed storage tier,
repeated `--expect-status` flags fail when no matching object has an allowed
cached HTTP status, repeated `--expect-fresh-ttl-secs` flags fail when no
matching object has an allowed stored fresh TTL, repeated `--expect-body-bytes`
flags fail when no matching object has an allowed stored body size,
`--expect-cache-lock-enabled`, `--expect-cache-lock-wait-timeout-secs`,
`--expect-memory-tier-enabled`, `--expect-disk-tier-enabled`, and
`--expect-storage-tiers` fail when the selected cache policy does not match the
required stampede-protection or tier layout, `--expect-scope`,
`--expect-vhost`, and `--expect-route` fail when the
selected cache policy is not the intended scope, vhost, or route,
`--expect-namespace` fails when the internal cache namespace is not expected,
and `--expect-key-namespace` / `--expect-user-tag` fail when the selected
operator key namespace or purge user tag is not the intended cache isolation
boundary,
`--expect-objects` fails when the lookup does not find exactly the requested
number of matching objects across enabled tiers,
`--expect-ineligible` and `--expect-reason` fail when a negative cache-policy
decision is not the expected bounded reason,
`--expect-serve-stale-if-error` and `--expect-serve-stale-while-revalidate`
fail when no matching object is eligible for those stale-serving policies,
`--expect-purge-indexed` fails when no matching object is reachable through the
bounded purge index, and repeated
`--expect-cache-tag` flags fail when no matching object has the expected stored
cache tag. Repeated
`--expect-header-name` flags fail when no matching object has the expected
stored response header name. Repeated
`--expect-freshness-state fresh|stale|expired` flags fail when none of the
matching objects has an allowed freshness state.

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
integrated with Pingora cache locks. Disk-only admissions now stream response
body chunks into a bounded temp file under the cache root before atomically
committing the final object, avoiding whole-object admission buffering for the
disk tier. Reader-visible partial writes remain disabled until Fluxheim can
provide a safe tagged reader for in-progress objects.

## Adapter Requirements

A production adapter must:

- Enforce byte budgets, not only item counts.
- Refuse objects larger than `cache.max_object_bytes`.
- Preserve HTTP cache metadata, including status, headers, validators, freshness
  metadata, combined cache keys, primary keys, and user tags for index rebuilds.
- Implement full cache-header behavior for:
  `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Vary`, `Age`,
  `Accept-Ranges`, `If-None-Match`, `If-Modified-Since`, request
  `Cache-Control`, `Pragma`, `Range`, and `If-Range`.
- Implemented now: static validators/ranges/client refresh controls, proxied
  client refresh bypass, Pingora `Vary` variance keys with unsafe/sensitive
  `Vary` rejection, shared-cache refusal for `Set-Cookie` responses, `image/*`
  origin response admission for proxied image cache, and end-to-end smoke
  coverage for cached HIT `Age`, conditional `304`, byte-range `206`,
  `If-Range` match/mismatch behavior, validator-based upstream revalidation
  from origin `304`, stale-object refresh from origin `200`,
  stale-while-revalidate serving during a background
  refresh, stale-if-error serving after an upstream connection failure,
  cache-lock request collapsing for concurrent misses, `Vary` variant
  isolation, HEAD storage bypass that does not poison cached GET bodies, and
  disk HIT behavior after process restart.
- Keep CDN/browser cache headers configurable through header policy and
  examples instead of hardcoded provider-specific defaults.
- Avoid unbounded buffering for large responses. Implemented for memory by
  enforcing `cache.max_object_bytes`; implemented for disk-only cache admission
  by writing bounded response chunks to a temp file before final commit.
  Reader-visible partial streaming is still pending.
- Support request collapsing or integrate with Pingora cache locks. Implemented
  for memory, disk, and tiered cache policies through Pingora cache locks.
- Support hit-for-pass/pass-cache decisions for repeatedly uncacheable dynamic
  objects. Implemented as opt-in `pass_uncacheable_after` with a bounded
  short-lived in-memory decision table.
- Expose purge semantics for the future admin API. Implemented in the storage
  adapters and protected admin endpoint for single-key and same-host bulk exact
  invalidation, including vhost and route-scoped cache policies.
- Expose operator cache counters. Implemented through the protected
  `GET /_fluxheim/cache/status` admin endpoint.
- Have focused tests for hit, miss, oversized object, purge, and vhost key
  isolation behavior.
