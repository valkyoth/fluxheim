# Fluxheim 1.6.32 Release Notes

Fluxheim 1.6.32 continues the final native-runtime cutover work after the
cache/PHP adapter slice.

## Highlights

- Metrics configuration now supports optional `metrics.token_env` and
  `metrics.token_file` bearer-token sources for the native metrics service.
  The token file path is resolved with the normal safe-path rules and rejected
  when it is empty, unsafe, or below a group/world-writable parent.
- Native metrics service construction now loads the configured token source,
  stores it in zeroizing memory, redacts it from debug output, and enforces it
  with constant-time comparison for `GET`/`HEAD /metrics`. It also exposes a
  Fluxheim-native background service factory that binds the native HTTP/1
  metrics listener under the native supervisor.
- The Pingora compatibility metrics listener still relies on listener binding
  and network ACLs for access control until the final native runtime owns that
  listener, but Fluxheim now validates the native metrics token source at
  startup so bad token configuration fails before the cutover.
- The native runtime launch plan now carries a metrics service-policy row that
  records whether the final native `MetricsHttp` listener must enforce bearer
  auth, making token enforcement a diffable cutover contract instead of an
  implicit root-runtime detail.
- Stream and UDP proxy routes now expose Fluxheim-native background service
  task factories beside their Pingora compatibility services. The compatibility
  runtime validates those native factories at startup whenever stream or UDP
  services are enabled, so final native service registration exercises the same
  route parsing and listener task construction before the cutover.
- The compatibility runtime now also validates the native HTTP/1 host-router
  factory when the server plan reports the proxy surface as native-ready. This
  proves exact/wildcard host routing, default-vhost selection, trusted-proxy
  source parsing, and route proxy construction can be assembled as one native
  router before the production runner switches away from Pingora.

## Tests

- Added config tests for metrics bearer-token parsing, `token_env` parsing, and
  conflicting token sources.
- Added native metrics tests for token loading from a file source,
  authenticated scrape acceptance, unauthenticated rejection, and debug
  redaction.
- Added native metrics listener tests proving the bearer-token policy works
  over an actual local TCP scrape request and that the background service task
  binds and stops under the native supervisor, not only through the in-memory
  handler.
- Extended native runtime launch-plan tests and cutover evidence validation to
  cover metrics bearer-token service policy.
- Added a runtime test proving a native-ready HTTP/1 proxy config builds the
  full native host-router factory, not only the individual proxy candidate.
