# Fluxheim 1.4.2 Release Notes

Fluxheim 1.4.2 is a maintenance architecture release. It does not add a new
operator-facing proxy feature family; it splits the large proxy runtime into
focused modules so future `1.4.x` work can land without growing `proxy.rs`
again.

## Highlights

- Proxy module split: `proxy.rs` is reduced by roughly one quarter compared
  with the start of the 1.4.2 work. The remaining file is focused on Pingora
  request/session orchestration and runtime state coordination.
- Focused proxy domains:
  - `access_log` owns structured access-log event construction, request IDs,
    status classes, timing helpers, and response-byte accounting.
  - `auth_request` owns outbound auth-subrequest dispatch and allow/deny
    decisions.
  - `compression` owns response compression negotiation, encoder lifecycle,
    output bounding, and `Vary: Accept-Encoding` mutation.
  - `edge_policy` owns trusted-proxy parsing, IP ACLs, rate limiting,
    concurrency limits, and route/vhost certificate-fingerprint policy.
  - `route_policy` owns exact/prefix/regex route matching, method matching,
    regex capture extraction, and safe route path rewrites.
  - `traffic_mirror` owns bodyless mirror request construction, salted
    sampling, in-flight caps, and outbound shadow delivery.
  - `proxy_protocol` owns outbound PROXY protocol v1/v2 frame generation and
    the L4 connector that sends frames before upstream traffic.
  - `upstream_tls` owns upstream trust-root and client certificate/key loading.
  - `php_fpm` owns managed PHP-FPM process supervision, watchdog restart,
    generated pool configuration, FastCGI transport, response parsing,
    retry/timeout classification, and body spooling.
  - `proxy_cache` owns stateless request/response cache policy helpers,
    bounded range/slice planning, freshness, stale-serving, and cache response
    header policy.
  - `cache_api` owns admin/cache request and result DTOs so admin-facing
    response shapes no longer live in the proxy orchestration file.
  - `path_safety` owns shared traversal-safe forwarding path validation used by
    peer fill, route rewrites, and future forwarding code.
- Source-boundary rule: new feature domains should start in focused modules
  once they have independent config validation, tests, metrics, dependencies,
  or security policy.

## Security Hardening

- Shared path-safety validation removes duplicated traversal checks between
  route rewrites and forwarding/cache helper paths.
- Traffic-mirror sampling now includes a process-local random salt so request
  paths cannot be precomputed into predictable include/exclude buckets.
- The ACME certificate install path now uses platform-specific `rustix` file
  mode conversion, preserving Apple Silicon/macOS developer builds while
  keeping Linux Clippy warning-clean.

## Compatibility Notes

- No configuration migration is required from 1.4.1.
- Public cache/admin API type paths remain available through `crate::proxy::*`
  re-exports. The internal implementation now lives in `cache_api`.
- Existing cache, PHP-FPM, traffic mirror, auth request, compression, route
  rewrite, mTLS, PROXY protocol, and upstream TLS behavior is intended to be
  unchanged.
- `ProxySnapshot` remains in `proxy.rs` because it wraps private proxy runtime
  state. The moved cache API types are plain request/result shapes.

## Suggested Checks

Run the normal release gates before publishing:

```bash
scripts/validate-release-metadata.sh
cargo check --locked --no-default-features --features profile-development --bin fluxheim --bin fluxheim-acme
cargo clippy --locked --no-default-features --features profile-development --all-targets -- -D warnings
```

For image and package validation, also run the relevant Podman and RPM smoke
tests from `docs/build-and-podman.md`.
