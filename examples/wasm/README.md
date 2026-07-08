## Fluxheim Wasm Examples

These examples are source-level policy examples. Build the `.wat` files to
`.wasm`, place the compiled module under one of the configured
`wasm.plugin_roots`, and pin the module SHA-256 in config before enabling it in
production.

`cache-lookup-policy.wat` and `cache-store-policy.wat` demonstrate the bounded
1.7.5 cache-policy ABI:

- split cache keys by Fluxheim's symbolic mobile/desktop device class;
- apply a bounded short TTL;
- add the fixed `wasm-policy` cache tag;
- add the fixed stored response header `x-fluxheim-cache-policy: wasm`.

The example intentionally uses separate modules for lookup and store phases
because Fluxheim links only the host calls valid for the current phase. It also
uses fixed Fluxheim host-call IDs. Plugins cannot emit arbitrary cache-key
bytes, TTLs, tags, response headers, upstream targets, or filesystem paths
through this ABI.
