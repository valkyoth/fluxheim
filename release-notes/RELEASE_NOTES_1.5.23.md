# Fluxheim 1.5.23 Release Notes

Fluxheim 1.5.23 starts the cache-aware origin-protection line with a narrow,
operator-controlled origin-fill budget for Fluxheim-owned cache fill paths.

## Added

- Added `[cache.origin_protection]`, `[vhosts.cache.origin_protection]`, and
  route-scoped `origin_protection`.
- Added `max_concurrent_fills` to bound concurrent protected origin fills per
  vhost or route cache policy. The first protected path is range slice fill.
- When a protected range slice is missing and the origin-fill budget is
  saturated, Fluxheim returns a bounded `503` instead of falling through to the
  normal origin path.
- Added cache status fields and metrics for origin-protection rollout:
  `fluxheim_cache_origin_protection_enabled_policies`,
  `fluxheim_cache_origin_protection_max_concurrent_fills`, and the bounded
  cache policy activity event `origin_protected`.
- Extended `fluxheim cache-key` and `fluxheim cache-lookup` previews with
  origin-protection policy state plus
  `--expect-origin-protection-enabled` and
  `--expect-origin-protection-max-concurrent-fills` release-gate checks.

## Notes

- Origin protection is disabled by default.
- Existing cache locks still coalesce same-key fills. Origin protection is a
  separate vhost/route budget across distinct protected fills.
- This release intentionally does not rewire Pingora's generic proxy cache miss
  lifecycle. Broader miss/revalidation integration belongs to the follow-up
  cache/runtime boundary work.
