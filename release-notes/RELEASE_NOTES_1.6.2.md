# Fluxheim 1.6.2 Release Notes

Fluxheim 1.6.2 continues the Pingora-exit line by moving more cache-owned
runtime contracts into `fluxheim-cache`. The current HTTP proxy runtime still
uses Pingora's cache facade, so this release is an internal independence step
rather than a behavior change for operators.

## Changed

- Moved cache key identity, serialized object envelopes, disk cache index
  entries, and disk index management into `fluxheim-cache`.
- Moved plaintext disk cache object header sizing, encoding, and parsing into
  `fluxheim-cache`; encrypted disk cache handling remains in the root adapter
  until the native HTTP/cache cutover.
- Moved storage-bin layout, manifest, index-entry, object-location, and
  free-map allocation helpers into `fluxheim-cache`. The root adapter still
  owns safe file opening and symlink checks for storage-bin files.
- Added a crate-owned `FluxCacheStorage` interface with serialized cache
  metadata, hit handlers, miss handlers, purge operations, and metadata-update
  operations.
- Adapted memory, filesystem disk, storage-bin disk, disk-backend, and tiered
  cache storage to the native cache interface while preserving the current
  Pingora HTTP runtime adapter.
- Moved cache-tag grammar, normalization, encoding, decoding, limits, and
  default tag-header names into `fluxheim-cache`.
- Added regression tests proving memory and tiered memory-plus-disk cache
  storage can round-trip cached objects through the native interface.
- Added a Rust integration test that enforces
  `docs/pingora-dependency-exceptions.tsv` removal targets against
  `Cargo.lock`, so expired Pingora dependency exceptions fail during normal
  `cargo test`.
- Updated workspace, RPM, README, build documentation, and release notes to
  `1.6.2`.

## Notes

- `pingora-cache` intentionally remains in the build graph for profiles that
  compile the current Pingora HTTP proxy runtime. Final removal is tracked
  under the native HTTP/runtime cutover later in the 1.6 line.
