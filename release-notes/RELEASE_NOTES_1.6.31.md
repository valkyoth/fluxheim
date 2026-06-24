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
- PHP split-container path mapping for `SCRIPT_FILENAME` and safe
  `PATH_TRANSLATED` generation now lives in `fluxheim-php-fpm`, keeping dot
  segment, hidden path, backslash, and control-byte rejection shared.
- PHP request-path to `SCRIPT_NAME`/`PATH_INFO` parsing, allowed-extension
  matching, and deny-prefix checks now live in `fluxheim-php-fpm`; the proxy
  still owns static-file lookup and final execution decisions.
- PHP static-file to script-name mapping and slashless directory-index redirect
  decisions now live in `fluxheim-php-fpm`, sharing root confinement, hidden
  path rejection, and extension checks across native and compatibility paths.
- PHP static-offload target validation now lives in `fluxheim-php-fpm`,
  including X-Accel-Redirect control-byte rejection, X-Sendfile `fpm_root`
  mapping, and PHP-script offload blocking.
- PHP X-Accel-Expires TTL parsing and restrictive origin cache-policy detection
  now live in `fluxheim-php-fpm`, giving native PHP response handling the same
  cache safety rules as the compatibility path.
- PHP response-header stripping policy now lives in `fluxheim-php-fpm`,
  including hop-by-hop headers, `Connection` tokens, configured hidden headers,
  and static-offload internal headers.
- PHP custom error-page/status interception decisions now live in
  `fluxheim-php-fpm`, keeping native and compatibility response handling on one
  status policy.
- Shared PHP response/request policy now pre-reserves bounded `CONTENT_TYPE`
  joins, rejects extensionless static-offload files, ignores invalid
  `Connection` header tokens before response stripping, and asserts ASCII-only
  parser invariants.
- PHP `CONTENT_TYPE` joining now caps and validates during accumulation instead
  of building an oversized intermediate string before rejecting it.
- Pure local-static cache keys now use the explicit `fluxheim-static-v1;`
  prefix, matching the static-cache namespace used by the compatibility cache
  wrapper and making raw key inspection unambiguous.
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
- Added standalone `fluxheim-php-fpm` tests for split-container script
  filename mapping and unsafe `PATH_INFO` rejection, plus the existing root
  compatibility test for PHP `fpm_root` mapping.
- Added standalone `fluxheim-php-fpm` tests for direct script detection,
  front-controller fallback, PATH_INFO split mode, unsafe segment rejection,
  allowed-extension matching, and deny-prefix matching.
- Added standalone `fluxheim-php-fpm` tests for static file script-name mapping
  and directory-index redirect decisions, plus existing root compatibility
  coverage for slashless PHP directory indexes.
- Added standalone `fluxheim-php-fpm` tests for PHP static-offload path policy,
  plus root compatibility coverage for X-Accel-Redirect and X-Sendfile
  handling.
- Added standalone `fluxheim-php-fpm` tests for X-Accel-Expires TTL parsing and
  restrictive origin cache-policy detection, plus existing root compatibility
  coverage for absolute-epoch parsing.
- Added standalone `fluxheim-php-fpm` tests for PHP response-header strip lists
  and internal static-offload header names, plus existing root compatibility
  coverage for hidden response headers.
- Added standalone `fluxheim-php-fpm` tests for PHP error-page/status
  interception decisions, plus existing root compatibility coverage for PHP
  custom error pages.
- Extended PHP-FPM tests for extensionless static-offload rejection and invalid
  `Connection` token filtering.
- Added PHP-FPM tests proving `CONTENT_TYPE` rejects control bytes and
  over-limit joined values without retaining the oversized joined result.
- Updated standalone `fluxheim-cache` tests to assert the local-static key
  prefix is `fluxheim-static-v1;`.
- Re-ran targeted tests for native HTTP/1 client encoding, load-balancer
  persistence constant-time comparisons, and TLS secret handling after the
  dependency refresh.
- Re-ran the native runtime cutover evidence gate and the Pingora dependency
  policy gate against the 1.6.31 planning state.
