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
- Moved cache storage-plan DTOs into `crates/fluxheim-cache::plan`, keeping
  root `crate::cache` re-exports while the Pingora storage adapters remain in
  the root cache runtime.
- Moved cached object DTOs and `CacheStoreError` into
  `crates/fluxheim-cache::object`, keeping root `crate::cache` re-exports for
  memory-cache and test call sites.
- Moved cache request/key DTOs into `crates/fluxheim-cache::request`, with root
  `crate::cache` re-exports and root cache-key builders preserving the existing
  behavior.
- Moved cache range/slice request DTOs, single-range parsing, client range
  parsing, client-range resolution, and required-slice planning into
  `crates/fluxheim-cache::request`, leaving root `crate::proxy_cache` as the
  Pingora request-header and cache-key adapter.
- Moved Content-Range parsing into `crates/fluxheim-cache::request`, so
  range-cache admission and slice-object reconstruction share one pure parser.
- Moved pure cache freshness helpers for remaining TTL and synthesized
  Cache-Control freshness directives into `crates/fluxheim-cache::headers`.
- Moved Vary header parsing and configured request-header variance policy into
  `crates/fluxheim-cache::headers`, keeping root `crate::proxy_cache` focused
  on Pingora request hashing and adapter logic.
- Moved Vary request hash material framing into
  `crates/fluxheim-cache::headers`; root `crate::proxy_cache` now only adapts
  Pingora request headers and calls the Pingora hash function.
- Moved cacheable response Content-Type matching into
  `crates/fluxheim-cache::headers`, leaving root cache admission as the
  status/header adapter.
- Moved cache-bypass cookie and query-string matching, including
  percent-decoded query comparisons, into `crates/fluxheim-cache::headers`.
- Moved cache stale-serving event and status/error allow policy into
  `crates/fluxheim-cache::headers`, keeping Pingora error classification in
  root `crate::proxy_cache`.
- Moved response `Age` and `Cache-Control` max-age/s-maxage parsers into
  `crates/fluxheim-cache::headers`, leaving root response helpers as thin
  Pingora header adapters.
- Moved Cache-Control directive merge/replacement into
  `crates/fluxheim-cache::headers`, leaving root response mutation as a
  Pingora header adapter.
- Moved range response `Content-Range` and `Content-Length` validation into
  `crates/fluxheim-cache::request`, leaving root range-cache admission as the
  Pingora status/header adapter.
- Moved cache-key component formatting and the temporary HEAD cache bypass
  predicate into `crates/fluxheim-cache::request`, keeping root compatibility
  wrappers for existing proxy callers.
- Moved multipart slice range policy sizing into
  `crates/fluxheim-cache::request`, leaving root `crate::proxy_cache` as the
  config adapter.
- Moved cache Prometheus label classifiers into `crates/fluxheim-cache`,
  keeping root `crate::metrics` as recorder wiring.
- Moved cache purge-index state, purge-entry DTOs, storage-local purge result
  counters, and cache-key path matching helpers into
  `crates/fluxheim-cache::purge_index`. Root `crate::cache` keeps the existing
  compatibility type names while the Pingora storage implementations remain in
  the root runtime adapter.
- Started the `fluxheim-web` crate boundary by moving static directory-listing
  data/rendering helpers into `crates/fluxheim-web`. The root `crate::web`
  module re-exports the same types and renderer while keeping Pingora response
  serving in the root adapter.
- Moved static byte-range parsing into `crates/fluxheim-web`, keeping
  `crate::web` compatibility re-exports for the existing static response
  planner and tests.
- Moved static response planning, conditional request evaluation, weak ETag
  construction, and range response plan DTOs into `crates/fluxheim-web`.
  `crate::web` keeps the existing `StaticRequestConditions` compatibility
  adapter so proxy call sites and cache-refresh semantics are unchanged.
- Moved safe relative path and directory-listing path helpers into
  `crates/fluxheim-web`, leaving root static serving responsible for filesystem
  canonicalization and symlink checks.
- Moved configured web-root symlink detection into `crates/fluxheim-web`,
  keeping root `StaticFileServer` construction as the filesystem adapter.
- Moved static cache identity formatting into `crates/fluxheim-web`, keeping
  root `StaticFile` as the filesystem metadata adapter.
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
- Moved PHP-FPM effective timeout calculation, retry attempt/deadline policy,
  retryable status matching, and retryable error classification into
  `crates/fluxheim-php-fpm`, with root `crate::php_fpm` retaining the
  `StatusCode` compatibility adapter.
- Moved PHP-FPM endpoint selection and endpoint DTOs into
  `crates/fluxheim-php-fpm`, with root `crate::php_fpm` keeping compatibility
  re-exports for the proxy runtime and tests.
- Moved PHP-FPM response-header name/value safety guards into
  `crates/fluxheim-php-fpm`, keeping root response parsing as the Pingora
  header adapter.
- Moved PHP-FPM response split, `Status` parsing, ASCII trimming, and header
  colon splitting into `crates/fluxheim-php-fpm`, leaving root response parsing
  as the Pingora response-header adapter.
- Moved managed PHP-FPM instance-name generation and metric-pool sanitization
  into `crates/fluxheim-php-fpm`, leaving root process supervision as the
  Unix runtime adapter.
- Started the `fluxheim-geoip` crate boundary by moving `GeoContext` and the
  optional local MMDB runtime into `crates/fluxheim-geoip`, with root
  `crate::geo_context` and `crate::geoip` compatibility re-exports.
- Started the `fluxheim-compression` crate boundary by moving response
  compression encoder lifecycle and output-limit accounting into
  `crates/fluxheim-compression`, while keeping Pingora header selection and
  response mutation in the root adapter.
- Moved Accept-Encoding token and qvalue parsing into
  `crates/fluxheim-compression`, keeping root response-header selection as the
  Pingora adapter.
- Moved compression response policy string matching for Cache-Control directives
  and Content-Type eligibility into `crates/fluxheim-compression`, leaving root
  response-header iteration as the adapter.
- Moved active Content-Encoding classification and compression input-size bounds
  into `crates/fluxheim-compression`, keeping root response headers/config as
  adapters.
- Started the `fluxheim-observability` crate boundary by moving W3C Trace
  Context parsing, generation, and traceparent normalization into
  `crates/fluxheim-observability`, with root `crate::trace_context` kept as a
  compatibility re-export.
- Moved the shared OTLP HTTP agent and symlink-safe custom CA bundle loader into
  `crates/fluxheim-observability` behind its `otlp-http` feature, while keeping
  the root `crate::otlp_http` module as the metrics/tracing adapter.
- Moved OTLP HTTP endpoint parsing into `crates/fluxheim-observability`,
  keeping the Prometheus metrics payload conversion in the root metrics adapter.
- Moved the Prometheus-to-OTLP metrics payload builder into
  `crates/fluxheim-observability` behind its `otlp-metrics` feature, leaving
  root metrics OTLP as exporter lifecycle and HTTP post wiring.
- Moved access-log helper logic for request-id validation/generation,
  shared low-cardinality status classes, response byte counting, and Unix
  nanosecond timestamps into `crates/fluxheim-observability`, while the root
  access-log module keeps Pingora request-header integration and JSON event
  assembly and Prometheus metrics reuses the shared status-class helper.
- Moved proxy metrics outcome, method, and status-class label bucketing into
  `crates/fluxheim-observability`, keeping root `crate::metrics` as the
  Prometheus registry/recorder adapter.
- Moved general Prometheus label classifiers for host-routing, admin-auth,
  compression, edge-policy, load-balancer event/queue/upstream, stream, ACME,
  PHP/PHP-FPM, and metrics-OTLP exporter events into `crates/fluxheim-observability`,
  further narrowing root `crate::metrics` to recorder wiring.
- Moved Prometheus numeric helper logic for bounded ratios and saturating gauge
  conversions into `crates/fluxheim-observability`, leaving root metrics as the
  registry/recorder adapter.
- Moved `LoadBalanceSelection` metric-label mapping into `fluxheim-config`,
  keeping root `crate::metrics` as a compatibility wrapper.
- Moved config-derived cache and load-balancer metrics summary aggregation into
  `fluxheim-config`, leaving root metrics to only publish the Prometheus
  gauges.
- Moved the OTLP trace exporter and trace-span payload builder into
  `crates/fluxheim-observability` behind its `otlp-trace` feature, with root
  `crate::otel_otlp` kept as a compatibility re-export.
- Started the `fluxheim-protocol` crate boundary by moving PROXY protocol v1/v2
  upstream header framing into `crates/fluxheim-protocol`, while the root
  `crate::proxy_protocol` module keeps the Pingora L4 connector adapter.
- Moved route method matching and prefix-boundary helpers into
  `crates/fluxheim-protocol`, keeping root `crate::route_policy` as the config,
  regex-capture, and Pingora request adapter.
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
