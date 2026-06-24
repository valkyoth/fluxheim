# Fluxheim 1.6.31 Release Notes

Fluxheim 1.6.31 starts the cache/PHP native-integration slice of the Pingora
exit work.

## Highlights

- Native HTTP/1 proxy planning now reports cache policy and PHP-FPM gaps with
  explicit blocker reasons instead of folding them into the generic HTTP policy
  bucket.
- Direct native route-proxy construction now fails closed for vhost/route cache
  and PHP-FPM policies until those adapters are implemented, so callers cannot
  bypass the planner and silently drop policy.
- Image/static cache request eligibility and cache-key construction now live in
  the Pingora-independent `fluxheim-cache` crate. The root compatibility module
  only wraps those shared keys into Pingora cache keys while that runtime path
  remains.
- The remaining normal-profile Pingora dependency exception target is now
  aligned with the roadmap: 1.6.31 is the cache/PHP adapter release, and 1.6.32
  remains the final Pingora-free proof release.

## Test Notes

- Added server-plan tests for root cache, vhost cache, route cache, vhost
  PHP-FPM, and route PHP-FPM native cutover blockers.
- Added route-proxy builder tests proving vhost/route cache and PHP-FPM
  policies are rejected directly until native adapters own those paths.
- Added standalone `fluxheim-cache` tests for cache-key construction,
  namespace/query/host normalization, and local-static file identity.
- Re-ran the native runtime cutover evidence gate and the Pingora dependency
  policy gate against the 1.6.31 planning state.
