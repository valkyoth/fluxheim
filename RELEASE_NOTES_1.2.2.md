# Fluxheim 1.2.2 Release Notes

## Release Metadata

- Version: `1.2.2`
- Release date: 2026-05-13
- Git tag: `v1.2.2`
- Release type: focused storage-bin cache follow-up

## Summary

Fluxheim `1.2.2` adds the focused slab/bin-style disk cache backend planned
after `1.2.1`. The existing filesystem disk cache remains the portable default,
while operators can opt into `cache.disk.backend = "storage-bin"` for large,
high-churn cache workloads that should avoid one-file-per-object storage.

## Highlights

- Added `cache.disk.backend = "storage-bin"` runtime selection while keeping
  the existing filesystem backend as the default.
- Added the storage-bin disk cache backend with manifest files, deterministic
  bin files, durable object index recovery, reusable free ranges, and LRU
  eviction parity.
- Added management parity for storage-bin cache stats, activity reset, exact
  purge, indexed hard/soft purge, stale purge, cache lookup, and cache warm
  workflows.
- Debounced durable storage-bin index writes after insert, eviction, and purge
  bursts to reduce write amplification under high-cardinality cache fills.
- Added clean shutdown flushing for pending storage-bin index updates.
- Added same-key rewrite handling so revalidation or object replacement can
  release and reuse the previous range.
- Added conservative tail-bin reclamation so eviction and purge can remove
  fully-free highest-numbered bin files without moving live objects.
- Exposed storage-bin pressure stats through admin JSON and Prometheus gauges,
  including allocated bin bytes, reusable free bytes, free range count, largest
  free range, and bin file count.
- Added `examples/cache-storage-bin.toml` plus CI and smoke coverage for the
  storage-bin backend.

## Validated Scope

- Local gate passed before release prep:
  - `cargo test -q storage_bin --lib`
  - focused storage-bin rewrite, drop-flush, and tail-reclaim tests
  - `cargo check --features profile-observability,acme-client`
  - `cargo check --no-default-features --features proxy,web,cache,tls-rustls,security`
  - `cargo clippy --features profile-observability,acme-client --all-targets -- -D warnings`
  - `sh scripts/smoke_storage_bin_cache.sh`
  - `cargo run --quiet -- --check-config --config examples/cache-storage-bin.toml`
  - `perl scripts/check-doc-links.pl`
  - `scripts/validate-release-metadata.sh`
  - `git diff --check`

## Known Limits

- The storage-bin backend is opt-in in `1.2.2`; the filesystem backend remains
  the default until production testing proves the bin format across more
  deployment shapes.
- Storage-bin compaction is conservative and only reclaims fully-free tail
  bins. Moving live objects between bins is reserved for a later compaction
  pass if production data shows it is needed.
- Partial streaming admission and range-slice fill remain future cache work.
- Optional cache encryption at rest, including local-key and OpenBao
  Transit/KMS key providers, is planned for `1.2.3`.
- Distributed cache metadata and peer-fill are planned for `1.2.4`.
- Wasm-based extension points, including cache-rule hooks comparable to VCL/Lua
  style customization, are planned for `1.4`.

## Checksums And Signatures

Record during the release:

- Commit: `v1.2.2` tag target
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
