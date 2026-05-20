# Fluxheim 1.3.3 Release Notes

## Summary

Fluxheim 1.3.3 is the PHP-FPM hardening and production-compatibility follow-up
for the 1.3 line. It focuses on WordPress and framework migration behavior,
safer php-fpm operation under load, bounded configuration surfaces, and RFC
response correctness discovered during production and pentest testing.

- Release type: compatibility and hardening follow-up
- Compatibility: no broad config break intended
- Primary area: PHP-FPM, WordPress migration, bounded config, and HTTP
  correctness

## Highlights

- Added opt-in php-fpm keepalive pooling with idle pruning through
  `[vhosts.php.fpm]` settings.
- Added safe custom FastCGI parameters with `[vhosts.php.params]` and
  `[vhosts.routes.php.params]`, while preventing overrides of Fluxheim-managed
  CGI variables.
- Added split filesystem-root support with `php.fpm_root` and optional final
  root symlink resolution with `php.resolve_root_symlink`.
- Added typed PHP routing presets with `php.try_files` and
  `php.preset = "wordpress"` for front-controller migrations without broad
  rewrite-string interpolation.
- Added `php.deny_path_prefixes` for defense-in-depth blocking of PHP
  execution under upload/file directories.
- Added `php.pass_request_headers`, `php.pass_request_body`,
  `php.hide_response_headers`, `php.ignore_origin_cache_headers`, and
  `php.intercept_error_statuses` for common NGINX/Caddy migration controls.
- Added PHP error-page support with `[[vhosts.php.error_pages]]` and
  route-level PHP error pages.
- Added configurable PHP response header caps and capped PHP response buffering
  through `php.max_response_header_bytes` and `php.max_response_bytes`.
- Added opt-in request-body disk spooling for large PHP uploads through
  `php.request_body_spool_threshold_bytes` and
  `php.request_body_spool_dir`.
- Added php-fpm TCP upstream lists, safe-method failover, retry windows, and
  invalid-response/status retry controls.
- Added PHP-specific Prometheus metrics and low-cardinality OTLP trace
  attributes for request outcome, retries, STDERR events, and keepalive pool
  state.
- Added PHP-assisted static offload for `X-Accel-Redirect` and `X-Sendfile`,
  plus `X-Accel-Expires` response handling.
- Added WordPress shared-cache safety helpers through `cache.preset =
  "wordpress"` for admin/login/path, cookie-prefix, query-string, and
  authorization bypasses.
- Added PHP app recipe documentation for Laravel, Symfony, Flarum, MediaWiki,
  phpBB, XenForo, MyBB, and Discourse-as-proxy. The review found no missing
  PHP-FPM protocol primitive for the PHP apps, but flat-root apps still need
  careful static path exposure until Fluxheim has generic static deny/allow
  policy.
- Capped major config collections, including upstream lists, header mutation
  policies, listener lists, trusted proxies, vhosts, routes, ACME issuers and
  domains, TLS allow-lists, static index files, cache key parts, and metric/log
  label names.
- Hardened HTTP behavior for RFC 9110/9112 findings: ACME 405 responses now
  include `Allow`, proxied messages append `Via`, chunked bodies without
  `Content-Length` are accepted, satisfiable static multi-range requests fall
  back to full responses, and generated text error bodies include
  `Content-Type`.
- Hardened admin throttling so exhausted per-source tracking fails closed with
  a global lockout.
- Updated `base64-ng` to `1.0.0`.

## Notes

Super Cache/W3TC static cache-file probing is not part of 1.3.3. The
implemented WordPress cache preset is a shared-cache safety preset. Static-file
fallback probing remains future work and should use typed file-probing rules
rather than arbitrary rewrite-string interpolation.

FastCGI multiplexing, authorizer, filter, and management roles remain
unsupported in 1.3.x. Fluxheim's PHP-FPM path supports the normal
one-request-at-a-time `FCGI_RESPONDER` web-serving subset.

## Build

Build the PHP-FPM release profile explicitly:

```bash
cargo build --release --locked --no-default-features \
  --features profile-web-server,php-fpm,acme-client \
  --bin fluxheim --bin fluxheim-acme
```

Build the standalone config tester release artifact:

```bash
cargo build --release --locked --no-default-features \
  --features profile-development \
  --bin fluxheim-config-tester
```

## Checksums And Signatures

To be filled during release.
