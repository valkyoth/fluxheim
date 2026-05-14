# Fluxheim 1.2.6 Release Notes

## Summary

Fluxheim 1.2.6 is a focused cache follow-up for full slice-based range cache
composition. It extends the 1.2.5 exact bounded range cache with an opt-in
fixed-slice engine for large proxy-cache objects.

- Release type: focused slice-cache follow-up
- Compatibility: opt-in; existing cache range behavior remains unchanged unless
  `range.slice.enabled = true`
- Primary area: proxy cache

## Added

- Added `[cache.range.slice]`, `[vhosts.cache.range.slice]`, and route-scoped
  slice policy.
- Added normalized slice cache keys for fixed-size byte slices.
- Added direct slice-cache response composition before upstream proxying.
- Added bounded missing-slice fill from origin using normalized single-slice
  `Range` requests.
- Added per-slice request collapsing so concurrent clients requesting the same
  missing slice do not all fetch it from origin.
- Added support for:
  - bounded ranges, such as `Range: bytes=1000-1999`;
  - open-ended ranges, such as `Range: bytes=1000-`;
  - suffix ranges, such as `Range: bytes=-65536`;
  - multipart multi-range responses when all requested ranges can be composed
    from fresh compatible slices.
- Added `If-Range` handling for slice responses. Fluxheim serves from slices
  only when the cached `ETag` or `Last-Modified` matches; otherwise the request
  falls back to the normal proxy path.
- Exact admin purges remove all indexed slice entries for the same request path
  when slice caching is enabled.

## Config Example

```toml
[cache.range]
enabled = true
max_bytes = "128MiB"

[cache.range.slice]
enabled = true
size_bytes = "1MiB"
max_slices = 128
fill_missing = true
```

## Safety Model

- Slice caching remains disabled by default.
- Each slice is stored under its own key and cannot collide with full-object
  cache entries or 1.2.5 exact range entries.
- Missing-slice fill only stores upstream `206 Partial Content` responses whose
  `Content-Range`, `Content-Length`, content type, total object length, and
  validators are compatible.
- `Content-Encoding` responses are not admitted to the slice cache unless they
  are explicitly identity encoded.
- `range.slice.size_bytes` must not exceed `cache.max_object_bytes`.
- `range.max_bytes` must not exceed
  `range.slice.size_bytes * range.slice.max_slices`.

## Validation

Release validation should include:

```bash
cargo fmt --all --check
cargo test --lib
cargo clippy --all-targets -- -D warnings
sh scripts/smoke_proxy_cache.sh
```

The proxy cache smoke now verifies slice fill, slice hit, open-ended ranges,
suffix ranges, multipart multi-range composition, and cached slice `If-Range`
matches.
