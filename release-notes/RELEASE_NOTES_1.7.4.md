# Fluxheim 1.7.4 Release Notes

Fluxheim 1.7.4 starts the VCL-like cache-policy part of optional WebAssembly
extensibility. The first live cache hook is intentionally constrained: plugins
can decide whether cache lookup proceeds, passes through origin, bypasses
cache, skips storage after an origin response, or denies, but cannot yet mutate
raw keys, TTLs, tags, response headers, or stored metadata.

## Highlights

- Add live native HTTP/1 `cache-lookup` Wasm hook execution for vhost and route
  attachments.
- Add live native HTTP/1 `cache-store` Wasm hook execution after origin
  response and before memory/disk cache writes.
- Add a bounded `fluxheim_cache_lookup() -> i32` preview ABI under the existing
  `fluxheim_policy_v1` host-call namespace.
- Add cache lookup outcomes:
  - `0`: continue normal cache lookup and storage;
  - `1`: pass through origin without lookup or storage;
  - `2`: bypass cache lookup and storage;
  - `3`: deny with `403`.
- Add cache store outcomes:
  - `0`: continue normal cache storage;
  - `1`: serve the origin response but skip storage;
  - `2`: deny with `403`.
- Apply cache-lookup hooks before native proxy-cache slice lookup, normal
  lookup, peer-fill, request collapsing, origin-fill protection, and store
  admission.
- Thread selected route/vhost Wasm hooks into route-proxy cache paths so cache
  decisions use the same attachment model as access, header, and route hooks.
- Add `wasm.max_total_cache_concurrent_executions` as a separate process-wide
  admission ceiling for `cache-lookup` and `cache-store` hooks.
- Add live listener tests proving a plugin can pass `/api/*` without storing
  while normal cacheable paths still produce `MISS` then `HIT`.
- Add live listener tests proving a plugin can skip storage after an origin
  response and deny before cache write/client delivery.
- Add live listener coverage proving a later cache-store `deny` wins over an
  earlier `skip`.
- Add fail-closed live coverage for cache-lookup deny behavior.

## Security Notes

- The cache-policy hooks are constrained to integer outcomes and coarse path or
  response-status context. They do not expose raw headers, bodies, filesystem,
  network, admin APIs, private keys, cache-key bytes, or cached object bodies.
- Built-in access policy, rate limits, concurrency limits, route selection, and
  header policy keep their normal order; the cache hook cannot bypass them.
- Cache hooks use their own process-wide cache admission ceiling so hot
  cache-policy routes cannot starve access-decision, route-decision, or header
  hooks on unrelated vhosts.
- Cache-store hook chains are most-restrictive-wins: every hook runs unless a
  hook returns `deny`, and `deny` wins over an earlier `skip`.
- Plugin execution failures still follow the configured fail mode:
  fail-closed denies with `503`, while fail-open continues normal cache
  behavior.
- The `wasm` feature remains optional and is still rejected with
  `privacy-mode`.
- The release gate updates `crossbeam-epoch` to `0.9.20` to clear
  `RUSTSEC-2026-0204`.

## Operator Notes

- Plugins that use `cache-lookup` export `fluxheim_cache_lookup() -> i32`.
- Plugins that use `cache-store` export `fluxheim_cache_store() -> i32`.
- `pass` and `bypass` outcomes report `x-cache-status: BYPASS` with
  `x-cache-reason: wasm-pass` or `wasm-bypass` when cache status headers are
  enabled.
- `pass` and `bypass` share the external `BYPASS` cache status but record
  distinct cache-policy activity as `pass` and `bypass`.
- Richer cache-policy hooks for bounded cache-key components, TTL override,
  tag assignment, store-admission mutation, and safe response-header mutation
  remain staged for later `1.7.x` slices.
