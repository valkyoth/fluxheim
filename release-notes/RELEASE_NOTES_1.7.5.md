# Fluxheim 1.7.5 Release Notes

Fluxheim 1.7.5 continues the VCL-like WebAssembly cache-policy milestone with
the first bounded cache-key and cache-store metadata hooks. The new host-call
surface is intentionally low-cardinality: plugins can add a symbolic
device-class cache variant, choose fixed TTL/tag metadata, and set one fixed
stored-object response header, but still cannot emit arbitrary key bytes or
mutate arbitrary cached response headers.

## Highlights

- Add a bounded `set_cache_key_component(label_id, value_id)` host call for
  `cache-lookup` Wasm hooks.
- Add symbolic `X-Device-Class` context under `context(5, 0)` for cache-policy
  plugins.
- Allow only the fixed `wasm-device-class=mobile` and
  `wasm-device-class=desktop` cache-key components in this slice.
- Add bounded `set_cache_ttl(ttl_id, 0)` and `add_cache_tag(tag_id, 0)` host
  calls for `cache-store` Wasm hooks.
- Allow only fixed TTL classes and fixed cache tags in this slice.
- Add bounded `set_cache_store_header(name_id, value_id)` for cache-store
  hooks, limited to fixed `x-fluxheim-cache-policy` values.
- Add bounded cache-store response content-type inspection through a symbolic
  `context(6, 0)` class, without exposing raw response headers.
- Thread Wasm-selected key components through native static-upstream and
  load-balanced proxy cache lookup paths.
- Thread Wasm-selected key components through fixed-slice range-cache keys so
  ranged mobile and desktop variants cannot share slice objects.
- Thread Wasm-selected TTL/tag metadata through native cache storage without
  exposing arbitrary response-header mutation.
- Thread fixed stored response-header metadata into the cached object while
  leaving the immediate origin MISS response unchanged.
- Add live native HTTP/1 listener coverage proving one URL can cache separate
  mobile and desktop variants, then HIT the original variant.
- Add live native HTTP/1 listener coverage proving Wasm-selected key
  components also isolate fixed-slice range-cache objects.
- Add live native HTTP/1 listener coverage proving a plugin TTL override
  expires an otherwise `max-age=60` object and refills from origin.
- Add live native HTTP/1 listener coverage proving a plugin can set the fixed
  stored response header on cache HIT and that forbidden header IDs fail
  closed.
- Add negative coverage proving duplicate stored-header mutations fail closed
  and stored-header mutation caps are enforced.
- Add negative coverage for aggregate cache-key component caps, cache-tag caps,
  and TTL singleton merge behavior.
- Add `examples/wasm/cache-lookup-policy.wat`,
  `examples/wasm/cache-store-policy.wat`, and a matching config template for
  the bounded cache-policy ABI.
- Add live native HTTP/1 listener tests that compile the checked-in example
  Wasm sources and prove image-only cache-store metadata, cache-key, TTL, and
  stored-header behavior.

## Security Notes

- Unknown component IDs, unknown values, duplicate component labels, and
  component counts above the hard cap fail through the plugin fail mode.
- Duplicate cache-key component labels and aggregate component counts are
  enforced across the full `cache-lookup` hook chain, not only within a single
  plugin invocation.
- Unknown TTL IDs, duplicate TTL overrides, unknown tag IDs, and tag counts
  above the hard cap fail through the plugin fail mode.
- Unknown stored-header IDs, duplicate stored-header mutations, and stored
  header mutation counts above the hard cap fail through the plugin fail mode.
- Cache-store metadata caps are scoped independently to TTL, tag, and stored
  header metadata so one exhausted metadata family cannot silently drop a later
  family.
- Oversized cache-store candidates are rejected before cloning response bodies
  for stored-header metadata mutation.
- Store hooks receive only symbolic content-type classes for response-header
  inspection; raw response header names and values remain unavailable.
- The hook does not expose arbitrary request headers, raw cache-key bytes,
  request bodies, response bodies, filesystem access, network access, or cached
  object contents.
- Built-in access, route, rate-limit, concurrency, header, and cache admission
  controls keep their normal order.

## Operator Notes

- This is a preview ABI for controlled cache-key variation. The only accepted
  cache-key label is currently `wasm-device-class`; the only accepted values
  are `mobile` and `desktop`.
- Store TTL, tag, and stored response-header choices are fixed IDs, not
  arbitrary strings. Richer store admission mutation and cache response policy
  hooks remain staged for later `1.7.x` slices.
