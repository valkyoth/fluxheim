# Fluxheim 1.3.1 Release Notes

## Summary

Fluxheim 1.3.1 starts PHP application support with an explicit `php-fpm`
compile-time module. It is intended for operators who want Fluxheim to serve
WordPress-style PHP applications directly through php-fpm while keeping PHP out
of default, cache, proxy, and privacy builds.

- Release type: PHP-FPM feature release
- Compatibility: opt-in build feature and opt-in vhost/route configuration
- Primary area: PHP-FPM config, secure script resolution, FastCGI response
  handling, docs, and feature-policy checks

## Highlights

- Added `php`, `php-fpm`, `php-turbine`, and `php-phprs` feature gates.
- Implemented the production `php-fpm` path through `fastcgi-client`.
- Added `[vhosts.php]` and `[vhosts.routes.php]` typed config.
- Added strict PHP script resolution below the configured PHP root.
- Added WordPress-style front-controller dispatch through `index.php`.
- Existing non-PHP files under the PHP root can still be served by the normal
  static file path.
- PHP request bodies are bounded before being sent to php-fpm.
- PHP response headers are parsed strictly and CRLF/control-byte injection is
  rejected.
- Added `examples/php-fpm.toml` and PHP runtime documentation.
- Added feature-policy checks that reject multiple PHP runtime features in one
  binary.

## Build

PHP-FPM is not compiled by default. Build it explicitly:

```bash
cargo build --release --locked --no-default-features \
  --features profile-web-server,php-fpm,acme-client
```

## Checksums And Signatures

To be filled during release.
