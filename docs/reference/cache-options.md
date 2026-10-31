# Cache Options

Start with the [caching guide](../guides/cache.md) and its complete runnable
examples. This reference describes the shared cache configuration model; it
does not imply that local-static, proxy and peer-fill paths implement identical
behavior. Native local-static caching is memory-only. Proxy `HEAD` bypasses
storage. The precise stale-error category limitation is recorded below.

Use these fields under `[cache]`, `[vhosts.cache]` or `[vhosts.routes.cache]`,
with nested tables under the same scope. Example assignments are individual
fields, not complete standalone server configurations. Byte sizes accept byte
counts or strings such as `"256KiB"`, `"8MiB"`, `"1GiB"`. Time fields here are
integer seconds unless their name says otherwise. Lists/maps supplied by a
configuration fragment replace the supplied field; do not assume list append.

## Activation And Storage Admission

| Field | Default | Meaning / example |
| --- | --- | --- |
| `enabled` | `false` | Activate cache policy; needs a compiled cache feature and at least one enabled tier |
| `local_static` | `false` | Include local web files; native support requires memory enabled and disk disabled |
| `preset` | none | `preset = "wordpress"` adds WordPress bypasses; not page-cache activation |
| `methods` | `["GET", "HEAD"]` | Request methods considered; native proxy HEAD still bypasses |
| `content_types` | See below | Response MIME allowlist for 200 responses, e.g. `["image/*", "text/css"]` |
| `image_extensions` | See below | URL extension allowlist; `extensions` is an alias, e.g. `extensions = ["css", "js"]` |
| `max_object_bytes` | `"32MiB"` | Positive maximum stored body; every enabled tier must be at least this large |
| `min_uses` | `1` | Positive admission threshold, e.g. `min_uses = 2`; not an authenticated popularity signal |
| `pass_uncacheable_after` | `0` | Zero disables threshold-based pass decisions; e.g. `3` temporarily passes repeatedly uncacheable keys |

Default content types: `image/*`, `text/css`, `text/javascript`,
`application/javascript`, `application/wasm`, `font/*`, `application/font-woff`,
`application/vnd.ms-fontobject`. Default extensions: `avif`, `css`, `eot`, `gif`,
`ico`, `jpeg`, `jpg`, `js`, `mjs`, `otf`, `png`, `svg`, `ttf`, `wasm`, `webp`,
`woff`, `woff2`. Lists are bounded: at most 64 content types, 128 extensions
and 16 methods. HTML/API caching is not implicitly enabled by these defaults.

## Keys And Variance

| Field | Default | Meaning / example |
| --- | --- | --- |
| `key_namespace` | unset | Optional isolation label, e.g. `"assets-v2"`; 1-128 ASCII letters/digits or `-_.:` |
| `key_parts` | `["method", "host", "path", "query"]` | Unique subset of these four fields; `path` required; dropping host/query requires a content-equivalence review |
| `include_query` | `true` | Include query material when `query` is in key_parts; false can share different query responses |
| `vary_request_headers` | `[]` | Additional safe request variation, e.g. `["accept-language"]`; max 16, sensitive identity headers rejected |

Origin `Vary` is separately checked. Variance is bounded and hashed; this is not
permission to cache secrets. A namespace change separates keys but does not
delete old objects. Cache keys and inspection output can expose request identity
and should be treated as operational data, not published as metrics labels.

## Request Bypass

All optional lists/maps below default to empty, except `bypass_query` which
defaults to false. Matching a bypass means neither reading a shared cached
response nor storing that request's origin response. Authorization and
Proxy-Authorization always bypass regardless of this configuration.

| Field | Example | Purpose |
| --- | --- | --- |
| `bypass_path_prefixes` | `["/private/", "/preview/"]` | Exclude URL path families |
| `bypass_path_exact` | `["/login", "/account"]` | Exclude individual paths |
| `bypass_request_headers` | `["cookie"]` | Header presence marks personalized traffic |
| `bypass_request_header_values` | `{ x-preview = "1" }` | Exclude a particular header value |
| `bypass_cookie_names` | `["sessionid"]` | Exclude a named session cookie |
| `bypass_cookie_name_prefixes` | `["session_"]` | Exclude cookie-name families |
| `bypass_cookie_values` | `{ preview = "1" }` | Exclude a selected cookie value |
| `bypass_query_params` | `["preview", "token"]` | Exclude a query parameter by name |
| `bypass_query_values` | `{ mode = "private" }` | Exclude a particular query value |
| `bypass_query` | `true` | Bypass requests with a query instead of removing the query from the key |

Query bypass examines raw and percent-decoded names/values. Path and cookie/query
lists/maps are capped at 128 entries; header lists/maps at 64. Do not rely on a
small list of known cookie names for an application that can introduce new
authentication cookies. The complete local recipe bypasses any Cookie header.

## Response Policy And Diagnostics

| Field | Default | Meaning / example |
| --- | --- | --- |
| `status_header` | unset | Optional debug header, e.g. `"x-cache-status"` |
| `status_reason_header` | unset | Optional rejection/reason header, e.g. `"x-cache-reason"`; review disclosure |
| `hide_response_headers` | `[]` | Remove selected origin headers before admission and delivery; stripping Set-Cookie removes a protection signal |
| `tag_headers` | `["surrogate-key", "cache-tag", "x-cache-tags"]` | Trusted origin tag sources for indexed purge; `[]` disables tag extraction |
| `no_store_response_headers` | `[]` | Reject storage when a header is present, e.g. `["x-private-response"]` |
| `no_store_response_header_values` | `{}` | Reject selected values, e.g. `{ x-app-cache = "private" }` |
| `ignore_origin_cache_headers` | `false` | Explicit override of origin cache-header policy; do not enable for private or mixed-public routes |
| `allow_client_cache_refresh` | `false` | Allow client no-cache/max-age=0/Pragma to force revalidation; no-store still bypasses |

Header collections are bounded and names validated. Tag headers must be unique
case-insensitively. Hop-by-hop response fields are stripped independently of
operator header policy. For standardized `Cache-Status` use the separate
response-metadata controls in the [configuration reference](config-reference.md).

## Freshness And Stale Responses

| Field | Default | Meaning / example |
| --- | --- | --- |
| `status_ttls` | `{}` | Positive seconds per response status, e.g. `{ "200" = 120, "404" = 15 }`; max 128 statuses in 100-599 |
| `default_status_ttl_secs` | unset | Positive fallback TTL for statuses; broad negative caching needs careful review |
| `stale_while_revalidate_secs` | unset | Positive stale refresh window, e.g. `10` |
| `stale_if_error_secs` | unset | Positive stale-error window, e.g. `60` |
| `stale_if_error_on` | All nine categories below | Select error kinds; must not be empty when stale-if-error enabled |
| `stale_if_error_statuses` | `[]` | Restrict eligible upstream 5xx statuses, e.g. `[502, 503, 504]`; empty leaves eligible 5xx unrestricted; at most 100 |

A configured TTL takes precedence over an otherwise valid origin freshness
value. Missing freshness requires an explicit TTL; invalid origin freshness
still rejects storage. Ordinary refusal rules are not disabled just by supplying
a TTL. Non-200 storage requires an explicit status/fallback TTL. These controls
do not make every status or zero-length response cacheable.

Accepted categories are `connect`, `timeout`, `read`, `write`,
`connection-closed`, `http-status`, `protocol`, `tls`, `other`. **Native limitation:**
the current I/O classifier never emits `read`, `write` or `tls`; it uses generic
I/O kinds instead of transport phase. the local follow-up  must resolve
this before the guide can promise phase-specific behavior. See the
[guide warning](../guides/cache.md#freshness-and-origin-failures).

## Memory, Disk And Storage Bins

| Table / field | Default | Constraints |
| --- | --- | --- |
| `memory.enabled` | `false` | Enable memory tier |
| `memory.max_size_bytes` | `"1GiB"` | Positive and at least max_object_bytes when enabled |
| `disk.enabled` | `false` | Enable persistent proxy tier |
| `disk.backend` | `"filesystem"` | `filesystem` or `storage-bin` |
| `disk.path` | unset | Required when enabled; config-relative or absolute trusted writable directory |
| `disk.max_size_bytes` | `"10GiB"` | Positive and at least max_object_bytes when enabled |
| `disk.storage_bin.bin_size_bytes` | `"256MiB"` | Positive, at least maximum object and no larger than disk budget |
| `disk.storage_bin.preallocate` | `false` | Preallocate bin files when enabled |
| `disk.storage_bin.max_open_bins` | `16` | Positive, manifest-bound setting; currently not enforced as a concurrent-open cap (the documented limitation; [maintenance](../guides/cache-recovery.md)) |

See the checked-in [filesystem](../../examples/cache/filesystem.toml) and
[bin](../../examples/cache/storage-bin.toml) fragments. The native memory path
tracks weighted object bytes, not `budget / max_object_bytes` fixed slots.
Budgets exclude some runtime/process overhead; disk does not eliminate body RAM.
Memory pruning uses expiry and stored age; disk eviction tracks access time.
For layout, tier behavior and initialization limits, see [cache backends](../guides/cache-backends.md).
Use [cache encryption](../guides/cache-encryption.md) for the nested
`disk.encryption` model, key permissions, key IDs and rotation.

## Fill Controls

| Table / field | Default | Meaning |
| --- | --- | --- |
| `lock.enabled` | `true` | Collapse simultaneous fills of the same key |
| `lock.age_timeout_secs` | `30` | Positive writer-age bound |
| `lock.wait_timeout_secs` | `30` | Positive total waiter budget; writer age can shorten it |
| `predictor.enabled` | `false` | Bypass keys after an uncacheable outcome using bounded short-lived counters |
| `predictor.capacity` | `65536` | Enabled capacity 1-1048576; not a guaranteed LRU eviction policy |
| `origin_protection.enabled` | `false` | Bound concurrent origin fills within a runtime policy; cache must be enabled |
| `origin_protection.max_concurrent_fills` | `32` | Enabled limit 1-1024 |

The native pass counters expire after 600 seconds. Explicit min-use admission
rejection does not seed the uncacheable predictor; other store rejections can.
The [policy example](../../examples/cache/policy.toml) combines a threshold,
bounded waits and origin protection. Do not confuse these with a distributed
rate limiter or a guarantee of end-user latency.

## Range And Maintenance Settings

| Table / field | Default | Meaning |
| --- | --- | --- |
| `range.enabled` | `false` | Opt into bounded proxy range caching |
| `range.max_bytes` | `"8MiB"` | Positive response-range budget; without slicing must not exceed maximum object |
| `range.slice.enabled` | `false` | Opt into fixed-slice storage/composition; requires range enabled |
| `range.slice.size_bytes` | `"1MiB"` | Positive slice size, no larger than maximum object |
| `range.slice.max_slices` | `128` | Positive slice count; max_bytes must fit size_bytes times max_slices |
| `range.slice.fill_missing` | `true` | Permit origin fetches for missing slices |

See the [range guide](../guides/cache-ranges.md) for validator/variance rules
and current memory-only slice storage and upstream-selection limitations
. Peer settings live under `peer_fill`; the
[peer guide](../guides/cache-peer-fill.md) covers every field and the confirmed
variant-context integrity gap. Encryption options and key
lifecycle are covered in [cache encryption](../guides/cache-encryption.md).

The separate global `[cache_purger]` table provides bounded stale cleanup:

```toml
[cache_purger]
enabled = true
interval_secs = 300
limit = 512
batches = 1
```

Defaults are disabled, 300 seconds, 512 objects and one batch. Interval is
1-86400 seconds, limit 1-100000 and batches 1-100. This is not a purge of every
fresh object or a substitute for byte-budget eviction. Use protected admin
operations for intentional invalidation. Native purge progress and disk dry-run
semantics currently have confirmed gaps; read the
[operations warnings](../guides/cache-operations.md#current-invalidation-warnings)
before relying on completion flags, periodic cleanup or a read-only preview.
