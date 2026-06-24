# Fluxheim 1.6.31 Release Notes

Fluxheim 1.6.31 starts the cache/PHP native-integration slice of the Pingora
exit work.

## Highlights

- Native HTTP/1 proxy planning now reports cache policy and PHP-FPM gaps with
  explicit blocker reasons instead of folding them into the generic HTTP policy
  bucket.
- The remaining normal-profile Pingora dependency exception target is now
  aligned with the roadmap: 1.6.31 is the cache/PHP adapter release, and 1.6.32
  remains the final Pingora-free proof release.

## Test Notes

- Added server-plan tests for root cache, vhost cache, route cache, vhost
  PHP-FPM, and route PHP-FPM native cutover blockers.
- Re-ran the native runtime cutover evidence gate and the Pingora dependency
  policy gate against the 1.6.31 planning state.
