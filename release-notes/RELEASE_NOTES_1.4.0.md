# Fluxheim 1.4.0 Release Notes

Fluxheim 1.4.0 is the first production proxy parity release. It consolidates
the planned edge-policy, upstream-resilience, TLS/identity, and HTTP/2/gRPC
proxy work into one larger 1.4 baseline instead of splitting it across several
small unreleased milestones.

## Highlights

- Edge policy controls: trusted-proxy-aware IP ACLs, local token-bucket request
  limits, in-flight concurrency limits, bounded delay/queue behavior, and
  Prometheus counters for policy decisions.
- Compression: opt-in gzip, Zstandard, and Brotli response compression with
  vhost and route overrides, MIME/size limits, output-size caps, conservative
  sensitive-response handling, and cache-safe `Vary: Accept-Encoding`.
  Official production profile aliases compile all three codecs; runtime config
  still controls which vhosts and routes use them.
- Upstream selection and resilience: weighted round-robin, least connections,
  power-of-two, source/URI/header/cookie hash selection, consistent-hash
  support, backup/drain policies, slow start, retry budgets, passive
  failure/5xx/latency ejection, and active HTTP health checks.
- Proxy rewrite controls: response `Location`, `Refresh`, and `Set-Cookie`
  domain/path rewrite rules plus route `rewrite_prefix` mapping for common
  NGINX/Apache reverse-proxy migrations.
- Observability: structured access log fields for trusted client IP, cache
  phase, route, selected upstream, downstream TLS identity, and applied
  compression; OTLP spans use resolved route identity and report compression.
- TLS and identity: listener client-certificate authentication, downstream TLS
  identity header template variables, route/vhost client-cert fingerprint
  policy, and admin client-cert fingerprint hardening for trusted terminators.
- Upstream protocol controls: upstream certificate and hostname verification
  controls, custom trust roots, upstream mTLS client certificates, PROXY
  protocol v1/v2 receive/send, upstream HTTP version selection, bounded HTTP/2
  controls, and route-scoped gRPC pass-through policy.
- Upstream connection tuning: total connection timeout, idle timeout, TCP
  keepalive, Linux user timeout, receive-buffer size, DSCP, and TCP Fast Open
  controls.

## Security Hardening

- Hardened route `strip_prefix` / `rewrite_prefix` forwarding against
  double-encoded traversal segments and decoded ASCII control bytes such as
  `%00`.
- Replaced concurrency-limit polling waiters with semaphore-backed permits and
  bounded `max_queue` waiters so saturated routes cannot create an unbounded
  wakeup loop.
- Changed admin and route/vhost client-certificate fingerprint list checks to
  compare across the full list without short-circuiting on the first matching
  byte prefix.
- Rejected TLS identity templates in request-header append policies. Use
  `add`/`set` for TLS identity headers so Fluxheim strips any inbound spoofed
  copy before forwarding the trusted value.
- Added `reject_indeterminate` to rate-limit policies so operators can reject
  requests when no effective client IP is available instead of sharing one
  anonymous bucket.
- Bounded process-global slice-cache fill concurrency keys and abort on a
  poisoned slice-fill lock.
- Removed the process ID from generated snapshot IDs returned by the
  authenticated admin API.
- Documented the shared anonymous rate-limit bucket used when no effective
  client IP is available, and added a startup security warning for
  admin-client-certificate header gates on loopback listeners.

## Compatibility Notes

- The new proxy controls are opt-in. Existing static, proxy, cache, PHP-FPM,
  ACME, and FIPS/ISO-capable configurations remain on their existing defaults
  unless the new config blocks are enabled.
- `[vhosts.concurrency]` and `[vhosts.routes.concurrency]` now accept
  `max_queue`; `0` derives a bounded queue size from `max_in_flight`.
- Compression requires the `compression` feature plus at least one codec
  feature: `compression-gzip`, `compression-zstd`, or `compression-brotli`.
  `privacy-mode` rejects compression at compile time.
- Client-certificate authentication requires a configured CA bundle and a TLS
  backend path that exposes the needed verification hooks. s2n remains
  fail-closed for client-auth and selected upstream PEM-loader paths until the
  backend can be wired without panic-prone helpers.
- gRPC support is pass-through only. Fluxheim does not perform gRPC-Web or JSON
  transcoding in 1.4.0.
- Dynamic upstream discovery, file-watched upstream lists, traffic mirroring,
  richer regex/template rewrites, local operational sockets, and typed hook
  points have been moved to the planned 1.4.1 proxy-operations release.

## Suggested Checks

Run the normal release gates before publishing:

```bash
scripts/validate-release-metadata.sh
cargo test --locked --features profile-core --lib
cargo clippy --locked --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp --all-targets -- -D warnings
```

For image and package validation, also run the relevant Podman and RPM smoke
tests from `docs/build-and-podman.md`.
