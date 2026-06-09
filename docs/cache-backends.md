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
- `cache.predictor`, `vhosts.cache.predictor`, and
  `vhosts.routes.cache.predictor` can opt into Pingora's cacheability
  predictor. The predictor keeps a bounded LRU of primary keys that recently
  produced origin-level uncacheable outcomes, allowing Fluxheim to bypass cache
  lookup and cache locking early for those keys. Fluxheim-specific custom
  policy reasons are skipped so explicit Fluxheim controls such as
  `min_uses`, configured bypasses, and response-header refusal policies remain
  observable through the existing policy counters.
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
- `allow_client_cache_refresh` is disabled by default so unauthenticated
  clients cannot force origin revalidation with `Cache-Control: no-cache`,
  `Cache-Control: max-age=0`, or `Pragma: no-cache`. Enable it only on
  narrowly scoped routes that intentionally expose browser-style refresh
  semantics. `Cache-Control: no-store` remains a full request bypass because
  the client forbids storage.
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
  cache-root children, ignore symlinked shards or objects, and scan every safe
  `.fhc` object so excess files cannot become untracked eviction orphans.
  Runtime stats and eviction use the maintained disk-object index instead of
  repeated filesystem scans. Purge, invalid-object cleanup, and eviction
  re-check the target immediately before deletion and only remove regular
  `.fhc` cache objects. Shard directories and object files must be
  symlink-free, even when a symlink points back inside the cache root; mount or
  configure the real cache directory path. Startup removes stale Fluxheim-owned
  disk-cache temp files from the root temp directory and deterministic shard
  temp locations after a conservative age threshold, while ignoring unrelated
  files and fresh temp files so snapshot reloads do not race active cache
  writers.
- `cache.disk.backend = "filesystem"` is the stable default disk backend. The
  `storage-bin` backend enables the focused `1.2.2` slab/bin storage line.
- The `[cache.disk.storage_bin]` table controls the first allocator settings:
  `bin_size_bytes`, `preallocate`, and `max_open_bins`.
- The storage-bin layout reserves a root-local
  `.fluxheim-storage-bin-v1` manifest and deterministic `bins/NNNN.fhbin`
  data files, with 16-digit hexadecimal bin ids. Object metadata will point to
  `(bin_id, offset, len)` locations that must fit entirely within a single bin;
  oversized objects remain rejected by the existing per-object cache limit.
- Startup creates the manifest atomically, reuses it on later starts, and
  rejects a storage-bin root if the manifest no longer matches the configured
  bin size, total byte budget, preallocation mode, or open-bin cap.
- Bin files are opened through the same no-follow disk-cache path helpers used
  by filesystem cache objects. Writes must match the allocated object length,
  reads are bounded by the recorded location, and `preallocate = true` expands
  new bin files to the configured bin size before object bytes are committed.
- The storage-bin backend can encode, allocate, store, read, purge, and release
  objects through the manifest/bin/free-map primitives. Restart recovery,
  eviction parity, the Pingora `Storage` implementation, and runtime backend
  selection are in place. The release gate includes a storage-bin smoke that
  verifies live proxy traffic populates the bin/index files and returns `MISS`
  followed by `HIT`.
- A root-local `.fluxheim-storage-bin-index-v1` records each combined cache key
  and its `(bin_id, offset, len)` location. On startup Fluxheim reads the index,
  validates each referenced object by parsing the v5 cache object bytes, rebuilds
  the purge index, and reconstructs free ranges from the occupied locations.
- Storage-bin index writes are debounced after insert, eviction, and purge
  bursts. A crash can drop the newest cache entries from the durable index, but
  the affected bin ranges are then treated as free on restart rather than
  becoming unbounded orphaned files. Clean storage teardown performs a
  best-effort flush when the debounced index is still dirty.
- The allocator model uses first-fit free-range reuse within bounded bins and
  refuses allocations once the configured disk-cache byte budget is exhausted.
  Free ranges are merged after release so evictions can make space without
  growing the number of bin files. When purge or eviction frees the
  highest-numbered bin files completely, Fluxheim reclaims those tail bins
  without moving live objects.
- Storage-bin eviction follows the same basic LRU contract as the filesystem
  disk cache: before admitting a new object it removes the oldest tracked
  objects until the projected encoded-byte total fits under
  `cache.disk.max_size_bytes`, releases their bin ranges, removes purge-index
  metadata, and persists the updated storage-bin index.
- Storage-bin management hooks mirror the filesystem tier: stats, activity
  reset, cache-key inspection, exact purge, indexed hard/soft purge by user tag,
  path prefix/pattern, or cache tag, and stale-object purge all operate through
  the durable storage-bin object index plus the in-memory purge index.
- Storage-bin stats report allocated bin bytes, reusable free bytes, free range
  count, largest free range, and bin file count through the admin cache JSON and
  Prometheus aggregate gauges. These are the first operational signals for
  fragmentation and space amplification under high-churn workloads.
- Optional cache encryption at rest is part of the `1.2.x` cache line after
  the storage-bin format is defined. It remains disabled by default. The local
  provider uses AES-256-GCM object encryption with a safe key file or
  systemd/container credential. The OpenBao Transit provider keeps key material
  outside Fluxheim, calls Transit encrypt/decrypt over HTTPS or loopback HTTP,
  and stores only the returned Transit ciphertext in the cache backend.
  Encrypted objects bind the configured key id and combined cache key as
  authenticated data. `examples/podman-compose-openbao.yml` and
  `scripts/smoke_openbao_cache_encryption.sh` provide an optional local
  OpenBao Transit smoke path for this provider; the script starts a dev OpenBao
  container, enables Transit, creates a cache key, and verifies a Fluxheim
  proxy-cache `MISS` followed by `HIT` without plaintext cache storage.
  `examples/cache-encryption-local.toml` and
  `examples/cache-encryption-openbao.toml` are validated example policies for
  local-key and OpenBao-backed storage-bin cache encryption. The release gate
  includes `scripts/smoke_cache_encryption_local.sh`, which verifies encrypted
  storage-bin cache traffic without requiring an external KMS. Operational key
  setup and rotation guidance lives in `docs/cache-encryption.md`.
- The `1.2.4` distributed-cache line starts with a safe `[cache.peer_fill]`
  policy contract. Peer fill is disabled by default, requires an enabled cache
  policy, bounds peers/timeouts/object size/concurrency, and validates peer
  origins. Proxy-cache requests with `Cache-Control: only-if-cached` are served
  only from a fresh local cache object; misses, stale objects, bypassed
  policies, or ineligible methods return `504` and do not contact origin. This
  gives outbound peer fill a safe no-origin endpoint. On a local proxy-cache
  miss, Fluxheim asks configured peers for that no-origin endpoint before
  falling back to origin according to `fail_open`; peer hits are stored locally
  and peer requests forward only host plus safe negotiation headers rather than
  client credentials. The example
  `examples/cache-peer-fill.toml` shows the current config shape for
  cache-cluster planning. `scripts/smoke_peer_fill_cache.sh` runs a local
  multi-node smoke that proves node-to-node `PEER-HIT`, no extra origin fetch,
  local post-fill `HIT`, `Vary` variants, fail-closed `504` without origin
  fetch, fail-open origin fallback, and peer-fill metrics. The configured
  `peer_fill.max_concurrent_requests` budget is enforced per vhost or route
  cache policy for active outbound peer fetches.
  Peer response `Age` is preserved during admission, so a peer-filled object
  stores only its remaining freshness instead of extending the origin TTL.
  Peer-filled responses with `Vary` are stored under the matching variant key,
  so later local hits preserve negotiated variants.
  Metrics builds expose aggregate peer-fill policy, peer-count, and concurrency
  gauges for rollout checks.
- New disk cache objects use the v5 object header, which stores the combined
  cache key, primary key, user tag, cache tags, and path-index metadata. On
  startup Fluxheim merges the root-local `.fluxheim-disk-index-v1` checkpoint
  with a deterministic shard scan, then verifies every referenced cache object
  before indexing it. Corrupt or unindexable `.fhc` objects are removed instead
  of left as untracked disk usage. The rebuild path then enforces the
  configured disk-size budget before serving traffic, so indexed scope, prefix,
  wildcard, tag, stale disk purges, stats, and eviction accounting survive
  process restarts without ignoring files outside the checkpoint. Runtime cache
  mutations mark the checkpoint dirty and coalesce persistence through a
  debounced background writer instead of rewriting and fsyncing the full index
  on every disk-cache insert; regression coverage asserts a burst of inserts
  schedules one delayed checkpoint instead of writing immediately per object.
  Checkpoint writes merge with existing checkpoint or shard-scan entries so
  separate vhost and route cache policies sharing one disk root do not erase
  each other's restart index state. Older v1-v4 disk objects remain readable,
  but earlier formats cannot fully rebuild every indexed purge metadata field
  because they did not store all of the v5 index fields.
  A later storage-bin backend should replace the full startup shard scan with
  an incremental durable index.
  Indexed admin purges use a live-object purge metadata index as a fast path
  and also scan live memory or disk object metadata to supplement missing
  mappings, so fast-index drift cannot make live cached objects immune to
  user-tag, path-prefix, wildcard, cache-tag, or stale purges. The fast index is
  not FIFO-capped; memory-cache eviction notifications remove entries for
  evicted objects, and disk-cache rebuilds reconstruct entries from live v5
  objects.
- Disk eviction maintains an ordered LRU view inside the runtime disk-object
  index. Admissions that need space walk only the oldest entries needed to free
  the target byte count instead of cloning and sorting the full disk inventory
  on every eviction cycle.
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
  provider-specific cache controls. Proxied image cache admission bypasses
  Fluxheim's cache when the request sends `Cache-Control: no-store`.
  Local static-file responses are still direct file reads by default. When a
  selected cache policy sets `local_static = true`, local `[vhosts.web]` files
  and route-scoped web actions can participate in the same cache policy model
  as proxied static assets. Fluxheim keys these entries by request identity plus
  canonical file identity metadata, prefers memory storage over disk when both
  tiers are configured, emits configured cache-status headers, and includes
  `Age` on local static cache hits. The cache-key, cache-lookup, and exact
  cache purge paths resolve local static files and use the same file-identity
  key when `local_static` is enabled.
  `Cache-Control: no-cache`, `Cache-Control: max-age=0`, and
  `Pragma: no-cache` are ignored by default for shared-cache protection; when
  `allow_client_cache_refresh` is enabled they keep cache lookup enabled and
  force Pingora to revalidate an existing stored object instead of treating the
  request as a plain bypass.
  Proxied image cache admission also refuses shared-cache
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
  downstream conditional/range handling when cache is enabled. Fluxheim also has
  an opt-in fixed-slice range cache for large proxy objects. Slice caching
  stores normalized byte slices, validates object identity with total length and
  validators, fills missing slices from origin with bounded single-slice range
  requests, collapses concurrent fills for the same slice, and composes fresh
  slices into bounded, open-ended, suffix, or multipart byte-range responses.
  The release smoke suite verifies proxy cache HIT behavior, cached-hit `Age`,
  cached `Last-Modified` preservation, conditional `304`, byte-range `206`,
  slice fill/hit composition, open-ended and suffix slice ranges, multipart
  slice responses, `If-Range` match/mismatch behavior, cache-status HIT headers on cached
  conditional/range responses, validator-based upstream revalidation from an
  origin `304`, persisted validator metadata after that revalidation,
  stale-object refresh from an origin `200`, stale-while-revalidate serving
  during a background refresh, stale-if-error serving after an upstream
  connection failure, cache-lock request collapsing for concurrent misses,
  `Vary` variant isolation, admin exact/bulk purge, stale dry-run, vhost
  prefix/tag/wildcard purge, and route-scoped purge against real cached objects
  after a Fluxheim process restart, and disk-cache HIT behavior after a restart
  without the origin available. The same smoke path asserts bounded
  Prometheus purge counters for exact, bulk, stale, prefix, tag, wildcard, and
  route-scoped index purge operations.
  HEAD requests intentionally bypass proxy cache storage with the bounded
  `method-head` reason; the smoke suite verifies those probes do not poison
  cached GET entries. Full HEAD-to-GET cache parity remains future
  compatibility work.
  Fluxheim preserves changed `Last-Modified` values when an origin returns
  `304 Not Modified` during proxy-cache revalidation. Changed `Vary` values
  during 304 revalidation are detected and treated as a no-store revalidation
  response, keeping the existing cached metadata instead of corrupting variant
  selection. Full changed-`Vary` re-keying remains a future Pingora-path
  improvement because the stored variance key must change together with the
  response metadata. Broader cache-header matrix tests across static and
  proxied responses remain useful hardening work.
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
  scope, prefix, and wildcard purges have useful live metadata coverage.
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
`fluxheim_cache_peer_fill_enabled_policies`, `fluxheim_cache_peer_fill_peers`,
and `fluxheim_cache_peer_fill_max_concurrent_requests` expose the aggregate
distributed-cache peer-fill rollout shape without peer names or URLs.
Policy-level cache activity events `peer_fill_hit`, `peer_fill_miss`,
`peer_fill_error`, `peer_fill_fallback`, and `peer_fill_fail_closed` expose
runtime peer-fill behavior with bounded labels and without peer names, URLs, or
cache keys.
The protected `GET /_fluxheim/cache/status` admin endpoint also reports
peer-fill enabled policy counts, peer counts, maximum concurrency, and per-vhost
or per-route peer-fill flags so operators can audit the selected policy shape
without exposing peer URLs.
`fluxheim_cache_operation_duration_seconds{scope,vhost,route,phase,operation}`
records Pingora cache lookup and cache-lock wait durations as bounded
histograms, so operators can distinguish slow storage reads from stampede wait
time without labeling cache keys, paths, queries, cookies, or request headers.
The OTLP metrics exporter includes histogram payloads, so the same timing
series is available to Prometheus-compatible scraping and OTLP collectors.
Aggregate storage-pressure gauges expose current memory and disk object
counts, byte usage, configured byte budgets, fill ratios, and purge-index entry
counts through `fluxheim_cache_memory_*` and `fluxheim_cache_disk_*` metrics.
These gauges intentionally avoid per-cache-key or per-path labels; vhost and
route level detail remains available through the protected admin cache-status
JSON.
`fluxheim_cache_purges_total{operation,scope,vhost,route,mode}`
records successful admin purge commands with bounded operation and mode labels;
  it does not label cache keys, paths, tags, wildcard patterns, hosts, or query
  strings. When `[cache_purger]` is enabled,
  `fluxheim_cache_purger_runs_total{outcome}` and
  `fluxheim_cache_purger_entries_total{result}` expose bounded background stale
  disk cleanup progress, including `truncated` runs that need larger or more
  frequent cleanup windows. `fluxheim_cache_purger_duration_seconds{outcome}`
  records bounded per-tick duration so operators can distinguish an idle
  cleanup loop from one falling behind or blocked on slow storage.
  `POST /_fluxheim/cache/activity/reset` resets vhost and route activity
  counters without clearing cached objects.
- `cache.status_header` can expose compact response debug states such as
  `HIT`, `MISS`, `STALE`, `BYPASS`, and `REVALIDATE`.
  `cache.status_reason_header` can expose
  bounded no-cache reasons such as `OriginNotCache`, `ResponseTooLarge`, or
  Fluxheim policy reasons such as `request-refresh`, `request-header`,
  `request-header-value`, `request-cookie`, `request-query`, `cache-min-uses`,
  and `cache-pass`. `request-refresh` means `allow_client_cache_refresh` is
  enabled and the client requested revalidation through `Cache-Control:
  no-cache`, `Cache-Control: max-age=0`, or `Pragma: no-cache`; Fluxheim keeps
  cache enabled and asks Pingora to revalidate the stored object instead of
  treating this as a full cache bypass.
  `Cache-Control: no-store` remains a bypass with `request-no-store` so the
  response is not admitted into the shared cache. The proxy cache smoke suite
  verifies opt-in refresh and `no-store` reasons end to end. Keep the reason
  header disabled unless actively debugging a cache policy.
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
  live metadata entries for a vhost or route and removes objects whose stored freshness window
  has expired. It is intended as an operator-controlled incremental cleanup
  command and as the same bounded primitive used by the optional
  `[cache_purger]` background disk cleanup loop. Add `dry_run=true` or
  `x-fluxheim-cache-dry-run: true` to count stale objects without deleting
  them; dry-run responses include `would_purge` plus per-tier
  `memory_would_purge` and `disk_would_purge`. Stale purge also accepts
  `batches` / `x-fluxheim-cache-batches`. Each batch obeys the same bounded
  scan limit; dry-runs intentionally execute one scan, and responses set
  `increase_limit_required = true` when the scan was truncated but another
  identical batch would not make progress. Non-dry-run stale purges rotate
  scanned fresh entries to the back of the purge index when the scan is
  truncated, so repeated batches can advance through fresh front pages and
  still reach stale objects later in the same vhost or route bucket without a
  full filesystem walk.
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
  controls. The background purger uses the same fresh-entry rotation as the
  admin stale purge, so a bounded run can keep making progress even when fresh
  entries sit before expired entries in the index. The admin endpoint remains
  available for explicit dry-runs and larger maintenance windows. Metrics
  include bounded run outcome, entry counts, and per-tick duration so operators
  can see whether cleanup windows need to be raised.

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
state, cache-lock wait timeout, cacheability predictor state, selected
memory/disk tier availability, and ineligibility reason when the request is not
admitted. `cache-lookup` also
checks the selected memory and disk tiers for matching objects and prints safe
metadata such as status, body size, freshness timestamps, cache tags, and stored
header names. It also reports a compact `freshness_state` plus
`serve_stale_while_revalidate` and `serve_stale_if_error` booleans, so incident
checks can distinguish a fresh object, an object still usable under stale
policy, and a fully expired object. `purge_indexed` tells whether indexed scope,
prefix, tag, wildcard, and stale purge operations can reach that object without
a full scan. It does not contact the upstream, read cached object bodies to
stdout, or dump stored header values by default. Use repeated
`--header "Name: value"` options to inspect negotiated cache variants that
depend on safe request headers such as `Accept-Language` or `Accept-Encoding`;
use `--host` for the Host header. For release scripts,
`cache-lookup --require-object` fails when
the selected key has no cached object, repeated `--expect-tier memory|disk`
flags fail when no matching object is present in an allowed storage tier,
repeated `--expect-status` flags fail when no matching object has an allowed
cached HTTP status, repeated `--expect-fresh-ttl-secs` flags fail when no
matching object has an allowed stored fresh TTL, repeated `--expect-body-bytes`
flags fail when no matching object has an allowed stored body size,
`--expect-cache-lock-enabled`, `--expect-cache-lock-wait-timeout-secs`,
`--expect-cache-predictor-enabled`,
`--expect-peer-fill-enabled`, `--expect-peer-fill-peers`,
`--expect-peer-fill-max-concurrent-requests`,
`--expect-memory-tier-enabled`, `--expect-disk-tier-enabled`, and
`--expect-storage-tiers` fail when the selected cache policy does not match the
required stampede-protection, peer-fill, or tier layout, `--expect-scope`,
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
live purge metadata index, and repeated
`--expect-cache-tag` flags fail when no matching object has the expected stored
cache tag. Repeated
`--expect-header-name` flags fail when no matching object has the expected
stored response header name. Repeated `--expect-header "Name: value"` flags
fail when no matching object has the exact expected stored response header
value, which lets smoke tests verify revalidation updated validators and
freshness metadata without printing every stored header. Repeated
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

Fluxheim owns the cache implementation and, since `1.5.13`, the internal cache
storage interface. `FluxCacheStorage`, `FluxHandleHit`, and `FluxHandleMiss`
capture the hit, miss, purge, metadata-update, and admission semantics used by
the memory, disk, storage-bin, and tiered memory-plus-disk backends. The current
Pingora HTTP proxy path still requires `Storage`, `HandleHit`, and
`HandleMiss`, so `cache.rs` exposes a narrow adapter layer for that edge rather
than letting the rest of the cache module depend on Pingora session-bound
traits.

Request collapsing remains integrated with Pingora cache locks while the HTTP
proxy path is still Pingora-backed. Disk-only admissions stream response body
chunks into a bounded temp file under the cache root before atomically
committing the final object, avoiding whole-object admission buffering for the
disk tier. Reader-visible partial writes remain disabled until Fluxheim can
provide a safe tagged reader for in-progress objects.

Additional Pingora cache primitives worth exposing as Fluxheim matures:

- `HttpCacheDigest` records cache lock wait time and lookup/header-read time.
  These are good candidates for low-cardinality Prometheus histograms and
  OpenTelemetry span attributes because they explain slow cache hits and
  stampede waits without exposing cache keys or paths.
- `CacheablePredictor` is exposed through opt-in `[cache.predictor]`,
  `[vhosts.cache.predictor]`, and `[vhosts.routes.cache.predictor]` settings.
  `cache-key` and `cache-lookup` report and can assert the selected predictor
  state with `--expect-cache-predictor-enabled`. Fluxheim skips custom
  Fluxheim policy reasons in the predictor so local min-use, bypass, and
  response-header refusal controls remain governed by Fluxheim counters.
- `ForcedFreshness::ForceExpired` is already used for bounded client refresh
  revalidation (`Cache-Control: no-cache`, `Cache-Control: max-age=0`, and
  `Pragma: no-cache`). Future force-miss or force-fresh controls should only be
  exposed through bounded admin/debug interfaces, not broad public request
  headers, because force-fresh can mask origin updates and force-miss can
  amplify origin load.
- `CachePut` can fill cache storage from a supplied HTTP response stream. This
  would let deploy tooling preload selected objects without loopback HTTP
  warmups while still using the same storage, metadata, and eviction paths.
  The existing `cache-warm` command remains the safest first interface because
  it exercises the real vhost, route, and admission policy.

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
  origin response admission for proxied image cache, opt-in bounded proxy
  `Range` caching for safe single byte windows, opt-in fixed-slice range
  composition for bounded/open-ended/suffix/multipart ranges, and end-to-end smoke
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
