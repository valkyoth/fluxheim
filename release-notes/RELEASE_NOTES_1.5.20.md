# Fluxheim 1.5.20 Release Notes

Fluxheim 1.5.20 starts the web, PHP-FPM, and cache boundary-preparation line
and carries forward the post-1.5.19 trusted-proxy validation fix.

## Changed

- Started the `fluxheim-cache` crate boundary by moving shared cache-header
  request/response directive parsing into `crates/fluxheim-cache`. The root
  crate keeps `crate::cache_headers` as a compatibility re-export, so runtime
  behavior and call sites are unchanged.
- Moved pure cache admin request/result/preview DTOs into
  `crates/fluxheim-cache::api`, with root `crate::cache_api` and
  `crate::proxy` re-exports kept for compatibility. Pure runtime totals and
  activity-reset DTOs also moved.
- Moved cache object metadata, activity stats, tier stats, object lookup, and
  vhost/route runtime stats into `crates/fluxheim-cache::api`. Root
  `crate::cache` and `crate::cache_api` keep compatibility re-exports so admin,
  CLI, metrics, and proxy call sites are unchanged.
- Started the `fluxheim-web` crate boundary by moving static directory-listing
  data/rendering helpers into `crates/fluxheim-web`. The root `crate::web`
  module re-exports the same types and renderer while keeping Pingora response
  serving in the root adapter.
- Started the `fluxheim-php-fpm` crate boundary by moving PHP-FPM timeout
  classification and bounded error-outcome helpers into
  `crates/fluxheim-php-fpm`, with the root PHP-FPM module re-exporting the same
  names for existing runtime and test code.
- Moved managed PHP-FPM restart-backoff and sanitized `PATH` fallback helpers
  into `crates/fluxheim-php-fpm`, again keeping the root module as the
  compatibility surface for existing code.
- Moved managed PHP-FPM config rendering and its config-value validators into
  `crates/fluxheim-php-fpm`, leaving root PHP-FPM process supervision as the
  compatibility adapter.
- Started the `fluxheim-geoip` crate boundary by moving `GeoContext` and the
  optional local MMDB runtime into `crates/fluxheim-geoip`, with root
  `crate::geo_context` and `crate::geoip` compatibility re-exports.
- Started the `fluxheim-compression` crate boundary by moving response
  compression encoder lifecycle and output-limit accounting into
  `crates/fluxheim-compression`, while keeping Pingora header selection and
  response mutation in the root adapter.
- Started the `fluxheim-observability` crate boundary by moving W3C Trace
  Context parsing, generation, and traceparent normalization into
  `crates/fluxheim-observability`, with root `crate::trace_context` kept as a
  compatibility re-export.
- Moved the shared OTLP HTTP agent and symlink-safe custom CA bundle loader into
  `crates/fluxheim-observability` behind its `otlp-http` feature, while keeping
  the root `crate::otlp_http` module as the metrics/tracing adapter.
- Moved the OTLP trace exporter and trace-span payload builder into
  `crates/fluxheim-observability` behind its `otlp-trace` feature, with root
  `crate::otel_otlp` kept as a compatibility re-export.
- Started the `fluxheim-protocol` crate boundary by moving PROXY protocol v1/v2
  upstream header framing into `crates/fluxheim-protocol`, while the root
  `crate::proxy_protocol` module keeps the Pingora L4 connector adapter.
- Started the `fluxheim-snapshot` crate boundary by moving the durable config
  snapshot store, metadata validation, rollback pointer handling, and
  symlink-safe filesystem writes into `crates/fluxheim-snapshot`, with root
  `crate::snapshot` kept as a compatibility re-export.
- Moved reload-impact classification into `crates/fluxheim-config`, with root
  `crate::reload` kept as a compatibility re-export for admin and CLI reload
  reporting.

## Fixed

- Allowed real provider IPv6 trusted-proxy ranges such as Cloudflare's
  `2a06:98c0::/29`. The `1.5.19` config-crate split preserved runtime IPv6
  CIDR support but made config validation too strict by rejecting trusted proxy
  IPv6 prefixes broader than `/32`.
