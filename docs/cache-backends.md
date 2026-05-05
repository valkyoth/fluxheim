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
- The first Pingora memory adapter stores complete objects only; it buffers up to
  `cache.max_object_bytes` and refuses anything larger.
- The first Pingora disk adapter stores complete objects below `cache.disk.path`
  using SHA-256-derived shard paths, same-directory temporary files, and atomic
  rename. It refuses objects above `cache.max_object_bytes`, evicts the oldest
  `.fhc` files when needed to enforce `cache.disk.max_size_bytes`, and refuses
  admission only when the incoming object still cannot fit after eviction.
- Partial-write streaming is explicitly disabled for the production memory
  and disk adapters until in-progress response buffering can be bounded for
  unknown-size origin responses.
- When both memory and disk tiers are enabled on a vhost, Fluxheim uses a
  tiered Pingora storage adapter: memory is L1, disk is L2, misses are written
  to both tiers, disk hits are promoted back into memory when they fit, and
  purge invalidates both tiers.
- The protected admin endpoint `GET /_fluxheim/cache/status` reports per-vhost
  and aggregate cache enablement, tiering, memory counters, disk counters, and
  cache activity counters for hits, misses, stores, refused stores, and purges.
  `POST /_fluxheim/cache/activity/reset` resets activity counters without
  clearing cached objects.
  `POST /_fluxheim/cache/purge` invalidates one cache key from the selected
  vhost. `POST /_fluxheim/cache/purge-bulk` invalidates multiple exact keys
  that share the same host, method, vhost, and optional original URL query.
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
