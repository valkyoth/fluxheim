# Fluxheim 1.4.1 Release Notes

Fluxheim 1.4.1 is the proxy-operations follow-up to the 1.4.0 production
proxy parity baseline. It focuses on HTTP migration blockers, dynamic upstream
operations, safe request shadowing, and local read-only operational visibility.

## Highlights

- Regex route matching: opt-in `server.regex_enabled = true` unlocks
  route-level `path_regex` using Rust's bounded regex engine. Exact and prefix
  routes still take priority, and fallback routes still run last.
- Regex capture variables: request-header templates and regex rewrite templates
  can use bounded route captures such as `{route.regex.0}`,
  `{route.regex.1}`, and `{route.regex.version}`.
- Regex path rewrite templates: regex routes can use `rewrite_template` for
  path-only upstream URI rewriting. Rendered paths keep the original query
  string and pass the same traversal and encoded-separator safety checks as
  other route rewrites.
- Method-based routing: route `methods = ["GET", "HEAD"]` filters let one path
  route to different actions or upstreams by HTTP method.
- WebSocket and HTTP upgrade proxying: `proxy.websocket = true` enables
  explicit HTTP/1.1 upgrade forwarding, requires an HTTP/1 upstream policy, and
  bypasses proxy cache behavior for upgraded connections.
- External auth subrequests: `[proxy.auth_request]` performs bounded preflight
  authorization for proxy actions, forwards only configured request headers,
  and can copy allow-listed auth response headers into the upstream request.
- Traffic mirroring: the optional `traffic-mirror` feature adds safe bodyless
  request shadowing with deterministic sampling, allow-listed headers, timeout
  budgets, bounded response draining, and per-vhost/route in-flight worker
  caps.
- Dynamic upstream discovery: load-balancer builds can use DNS-refreshed
  upstream pools with `upstream_dns_refresh_secs` or file-refreshed pools with
  `upstreams_file`.
- Read-only ops socket: `[admin.ops_socket]` exposes local Unix-domain status,
  cache status, snapshots, and health endpoints without enabling mutating admin
  operations.
- Access-log improvements: structured logs now include selected upstream alias
  and retry count for load-balanced proxy requests.

## Security Hardening

- Dynamic DNS and file upstream refresh work is kept off Tokio executor worker
  threads during runtime refreshes. The bootstrap path remains synchronous only
  where Pingora requires an immediately-ready initial load-balancer update.
- Traffic mirror work is capped per vhost/route mirror key so slow mirror
  endpoints cannot monopolize the shared blocking worker pool used by other
  proxy policy features.
- Regex routing is disabled by default and must be explicitly enabled globally
  before route regexes, regex capture templates, or regex-backed rewrite
  templates are accepted.
- Regex rewrite output is path-only and still runs through Fluxheim's safe
  forwarding-path validation.
- Auth subrequests and mirror requests use bounded copied headers, bounded body
  handling, and low-cardinality metrics labels.

## Compatibility Notes

- Existing exact and prefix route configs continue to work without enabling
  regex support.
- `rewrite_template` is available only on regex routes and cannot be combined
  with `strip_prefix` or `rewrite_prefix`.
- `upstreams_file` and `upstream_dns_refresh_secs` are intentionally separate
  from static weighted/aliased/backup/drain upstream metadata in this release.
  Use static `upstreams` when those metadata controls are required.
- Traffic mirroring mirrors safe bodyless methods only in this release. Request
  body mirroring, redaction, and transformation policies remain future work.
- `auth_request` is intentionally a bounded first slice. Broader typed policy
  hooks and arbitrary Wasm/Lua execution remain deferred.

## Roadmap Adjustment

The next `1.4.x` stop is now a maintenance architecture release:

- `1.4.2`: split the large proxy runtime into focused modules before adding
  more large proxy features.
- `1.4.3`: optional GeoIP/Geo-Context and advanced HTTP policy work.
- `1.4.4`: TCP stream proxy foundation.

## Suggested Checks

Run the normal release gates before publishing:

```bash
scripts/validate-release-metadata.sh
cargo check --locked --no-default-features
cargo clippy --locked --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp --all-targets -- -D warnings
```

For image and package validation, also run the relevant Podman and RPM smoke
tests from `docs/build-and-podman.md`.
