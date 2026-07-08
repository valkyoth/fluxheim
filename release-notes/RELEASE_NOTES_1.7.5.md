# Fluxheim 1.7.5 Release Notes

Fluxheim 1.7.5 continues the VCL-like WebAssembly cache-policy milestone with
the first bounded cache-key mutation hook. The new host-call surface is
intentionally low-cardinality: plugins can add a symbolic device-class cache
variant, but still cannot emit arbitrary key bytes.

## Highlights

- Add a bounded `set_cache_key_component(label_id, value_id)` host call for
  `cache-lookup` Wasm hooks.
- Add symbolic `X-Device-Class` context under `context(5, 0)` for cache-policy
  plugins.
- Allow only the fixed `wasm-device-class=mobile` and
  `wasm-device-class=desktop` cache-key components in this slice.
- Thread Wasm-selected key components through native static-upstream and
  load-balanced proxy cache lookup paths.
- Add live native HTTP/1 listener coverage proving one URL can cache separate
  mobile and desktop variants, then HIT the original variant.

## Security Notes

- Unknown component IDs, unknown values, duplicate component labels, and
  component counts above the hard cap fail through the plugin fail mode.
- The hook does not expose arbitrary request headers, raw cache-key bytes,
  request bodies, response bodies, filesystem access, network access, or cached
  object contents.
- Built-in access, route, rate-limit, concurrency, header, and cache admission
  controls keep their normal order.

## Operator Notes

- This is a preview ABI for controlled cache-key variation. The only accepted
  cache-key label is currently `wasm-device-class`; the only accepted values
  are `mobile` and `desktop`.
- TTL override, tag assignment, store-admission mutation, and richer cache
  response policy hooks remain staged for later `1.7.x` slices.
