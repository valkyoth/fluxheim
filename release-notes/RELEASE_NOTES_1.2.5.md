# Fluxheim 1.2.5 Release Notes

## Release Metadata

- Version: `1.2.5`
- Release date: to be filled
- Git tag: `v1.2.5`
- Release type: focused bounded range-cache follow-up

## Summary

Fluxheim `1.2.5` closes the remaining practical large-file cache gap before the
`1.3` load-balancer/proxy line. It adds opt-in bounded caching for safe single
`Range: bytes=start-end` proxy requests and keeps partial responses isolated
from complete-object cache entries.

## Highlights

- Added `[cache.range]`, `[vhosts.cache.range]`, and route-scoped range policy.
- Added `range.enabled` and `range.max_bytes` controls. `range.max_bytes` must
  be greater than zero and no larger than `cache.max_object_bytes`.
- Added range-specific proxy cache keys, so repeated requests for the same byte
  window can return cache hits without colliding with full-object keys.
- Admitted range-cache objects only when upstream returns `206 Partial Content`
  with matching `Content-Range` and `Content-Length` metadata.
- Rejected unkeyed upstream `206 Partial Content` responses from the normal
  full-object cache path to avoid partial-response cache poisoning.
- Added parser, selection, keying, and admission tests for the new range-cache
  behavior.

## Example

```toml
[vhosts.cache]
enabled = true
status_header = "x-cache-status"
content_types = ["application/octet-stream", "video/*", "image/*"]
max_object_bytes = "32MiB"

[vhosts.cache.range]
enabled = true
max_bytes = "8MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "512MiB"

[vhosts.cache.disk]
enabled = true
backend = "storage-bin"
path = "/var/cache/fluxheim/example"
max_size_bytes = "100GiB"
```

## Known Limits

- This release implements exact bounded range caching, not multi-slice assembly.
  If production needs Varnish-style slice composition for arbitrary large
  object ranges, that can move into a later media-edge/cache extension line.
- Suffix ranges (`bytes=-N`), open-ended ranges (`bytes=N-`), and multi-range
  requests are intentionally not admitted to the range cache.
- `If-Range` requests stay on the normal path so validator-match and
  validator-mismatch behavior remains controlled by the existing full-object
  range handling.

## Checksums And Signatures

Record during the release:

- Commit: `v1.2.5` tag target
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
