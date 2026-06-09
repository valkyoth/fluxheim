# Fluxheim 1.5.13 Release Notes

Fluxheim 1.5.13 starts the Fluxheim-owned cache interface line.

This is an internal architecture release. It keeps the shipped cache behavior
stable while moving cache implementations behind Fluxheim-owned traits.

## What Changed

- Added `FluxCacheStorage`, `FluxHandleHit`, and `FluxHandleMiss` as the cache
  implementation boundary.
- Moved memory, disk, storage-bin, disk-backend, and tiered cache storage
  implementations to the Fluxheim cache traits.
- Added a narrow Pingora adapter so the current HTTP proxy path can continue to
  use Pingora's session cache machinery without making cache implementations
  depend directly on Pingora's `Storage`, `HandleHit`, or `HandleMiss` traits.
- Moved storage-focused unit coverage onto the Fluxheim cache interface.

## Compatibility

- Existing cache configuration remains compatible.
- Memory, disk, encrypted disk, storage-bin, tiered, purge, stale,
  cache-lock, range/slice, and predictor behavior is intended to match
  1.5.12.
- This release does not change the on-disk cache format.

## Privacy Cache

`privacy-cache` remains planned but disabled. Normal cache is still
incompatible with `privacy-mode`.

The future design remains limited to explicitly public assets: no client-IP
cache keys, no `Cookie` or `Authorization` admission, no per-user variants, no
`private`/`no-store`/`Set-Cookie` storage, strict query-string defaults, and
bounded memory or encrypted short-TTL disk storage.

## Packaging Notes

- RPM and container documentation are updated for `1.5.13`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
