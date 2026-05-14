# Fluxheim 1.2.4 Release Notes

## Release Metadata

- Version: `1.2.4`
- Release date: to be filled
- Git tag: `v1.2.4`
- Release type: focused distributed-cache follow-up

## Summary

Fluxheim `1.2.4` focuses on distributed cache metadata and peer-fill. The first
slice adds the configuration contract for safe peer-fill clusters while keeping
the existing single-node cache behavior unchanged until runtime peer retrieval
is implemented and tested.

## Highlights

- Added `[cache.peer_fill]`, `[vhosts.cache.peer_fill]`, and
  route-scoped `peer_fill` policy configuration.
- Added bounded peer-list, timeout, object-size, concurrency, and fail-open
  settings for future peer-fill runtime behavior.
- Added strict peer-origin validation. Peers must use explicit HTTP(S)
  `host:port` origins, cannot include userinfo/query/fragment, and non-loopback
  HTTP requires `allow_insecure_http = true`.
- Added aggregate Prometheus gauges for peer-fill enabled policies, configured
  peers, and maximum configured peer-fill concurrency.
- Added `cache-key` and `cache-lookup` output plus expectation flags for
  selected peer-fill policy shape.
- Added peer-fill policy coverage to protected admin cache-status JSON.
- Added the first runtime primitive for safe peer fill: proxy-cache requests
  with `Cache-Control: only-if-cached` return a fresh local cache hit or a
  `504` miss response without contacting the origin backend.
- Added outbound peer-fill on proxy-cache misses. Fluxheim asks configured peers
  for `only-if-cached` hits, strips sensitive client headers from peer
  requests, stores valid peer hits locally, and falls back to origin only when
  `fail_open` allows it.
- Added `examples/cache-peer-fill.toml` as the focused validated fixture for
  the distributed-cache config shape.

## Known Limits

- This release line now has the cache-only serving primitive and outbound peer
  fetch. Peer-fill-specific metrics and operational cache-cluster smoke coverage
  are expected to land in later `1.2.4` slices before tagging.
- Peer base URLs intentionally require an explicit port for now to avoid
  ambiguity in private cache clusters.

## Checksums And Signatures

Record during the release:

- Commit: `v1.2.4` tag target
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
