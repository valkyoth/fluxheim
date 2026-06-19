# Fluxheim 1.6.16 Release Notes

Fluxheim 1.6.16 starts the native proxy cutover gate for the Pingora-exit line.
The release does not switch production traffic away from the compatibility
adapter yet; instead it makes native HTTP/1.1 proxy eligibility stricter and
more auditable so only configurations whose semantics are represented by the
native handler can be marked ready.

## Security and Correctness

- Native HTTP/1.1 proxy planning now fails closed when a route uses
  `strip_prefix`, `rewrite_prefix`, or `rewrite_template`. The native handler
  does not apply those request-path transforms yet, so these routes remain on
  the Pingora compatibility adapter until the native pipeline owns the same
  behavior.
- Vhost-level ACME challenge routing and vhost redirects now block native
  HTTP/1.1 proxy eligibility. Both features alter request routing before
  upstream forwarding and must be implemented explicitly before cutover.
- Proxy configs using auth subrequests, traffic mirroring, proxy error pages,
  advanced upstream transport settings, per-proxy downstream throttling, or
  advanced load-balancer policy now receive explicit compatibility-only
  reasons from the native proxy builder.
- Parsed TOML configs now receive the same proxy downstream write and
  total-response timeout defaults as `ProxyConfig::default()`. This keeps the
  native cutover readiness gate from treating omitted timeout fields as
  per-proxy overrides.
- `ServerPlan` now exposes a native HTTP/1.1 proxy cutover summary with
  `NoProxy`, `NativeReady`, `Mixed`, and `CompatibilityRequired` states. This
  gives the next runtime wiring release a single audited readiness signal
  instead of requiring callers to reinterpret every candidate row.
- Fluxheim now logs the native HTTP/1.1 proxy cutover readiness state at
  startup, including compatibility-only reasons for proxy paths that are not
  native-ready yet.

## Tests

- Added native HTTP/1.1 proxy tests for auth-request, traffic-mirror,
  error-page, upstream-transport, and downstream-policy blockers.
- Added server-plan tests proving route strip/rewrite and vhost ACME challenge
  routing keep affected proxy paths on the compatibility adapter.
- Added server-plan coverage for vhost redirects and TOML parsing coverage for
  proxy downstream timeout defaults.
- Added server-plan tests for aggregate native HTTP/1.1 cutover readiness.
- Native HTTP/1.1 TLS proxy tests now clean up temporary PEM fixture
  directories through a drop guard even if a test assertion panics.

## Compatibility

- The active runtime adapter remains `PingoraCompatibility` in this release.
  Native HTTP/1.1 proxy, upstream TLS, and HTTP/2 upstream primitives continue
  to be built and tested as staged cutover components.
