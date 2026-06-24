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
- `NativeHttp1Request` now implements the `fluxheim-cache` request-view trait,
  allowing the native proxy to reuse cache bypass, revalidation, range, and
  slice policy helpers without a Pingora request header.
- PHP-FPM response parsing now lives in the Pingora-independent
  `fluxheim-php-fpm` crate and returns plain status/header/body parts. The root
  proxy path only converts those parts into the current runtime response type.
- PHP FastCGI parameter value validation and request-header-to-param-name
  mapping now live in `fluxheim-php-fpm`, giving the native and compatibility
  paths one shared policy for bounded, control-free PHP params.
- PHP `SERVER_NAME` fallback selection now also lives in `fluxheim-php-fpm`,
  keeping host/fallback sanitization shared by native and compatibility paths.
- PHP FastCGI request-header param translation, resolved `HTTP_HOST` insertion,
  `CONTENT_TYPE` value selection, and runtime custom-param filtering now live
  in `fluxheim-php-fpm`; the current proxy path only applies those generated
  pairs to `fastcgi_client::Params`.
- Updated `sanitization` to 1.2.2 and `base64-ng` to 1.2.3 across the root,
  server, TLS, and load-balancer crates.
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
- Added native HTTP/1 tests proving cache request policy helpers work through
  `NativeHttp1Request` for origin-form and absolute-form targets, duplicate
  headers, and range-policy rejection.
- Added standalone `fluxheim-php-fpm` tests for plain PHP response parsing,
  unsafe header rejection, and response/header size limits, then re-ran the
  existing root parser compatibility tests with `php-fpm` enabled.
- Added standalone `fluxheim-php-fpm` tests for FastCGI param value bounds,
  control-byte rejection, and deterministic HTTP header param-name mapping.
- Added standalone and compatibility tests for PHP `SERVER_NAME` fallback
  behavior when the request host is unsafe.
- Added standalone `fluxheim-php-fpm` tests for duplicate request-header
  joining, `Proxy` header blocking, joined-value caps, safe `HTTP_HOST`
  insertion, content-type selection, and runtime custom-param filtering.
- Re-ran targeted tests for native HTTP/1 client encoding, load-balancer
  persistence constant-time comparisons, and TLS secret handling after the
  dependency refresh.
- Re-ran the native runtime cutover evidence gate and the Pingora dependency
  policy gate against the 1.6.31 planning state.
