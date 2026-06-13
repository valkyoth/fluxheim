# Fluxheim 1.5.21 Release Notes

Fluxheim 1.5.21 continues the UDP beta production-readiness line. The UDP
feature remains compile-gated behind `udp-proxy`, but DNS-style
request/response forwarding now has explicit pressure and observability
controls for safer testing.

## Added

- Added `udp.routes.max_sessions_per_source` to cap concurrent in-flight UDP
  datagram sessions per source IP.
- Added `udp.routes.max_responses_per_source_per_second` to cap UDP responses
  per source IP per one-second window.
- Added UDP Prometheus metrics:
  `fluxheim_udp_datagrams_total`, `fluxheim_udp_drops_total`, and
  `fluxheim_udp_active_sessions`.
- Added admin UDP status at `GET /_fluxheim/udp/status`.
- Added UDP passive upstream health controls:
  `passive_health_enabled`, `passive_health_failures`, and
  `passive_health_ejection_secs`.

## Changed

- `dns-load-balance` UDP routes now log a security warning when a beta route
  listens on a non-loopback address.
- UDP request/response pools skip passively ejected upstreams while at least
  one ready member remains, with fallback behavior when the full pool is
  unhealthy.
- UDP beta docs and smoke tests now describe and exercise the explicit
  per-source pressure controls.
- UDP smoke coverage now verifies exact-cap responses are accepted and
  oversized downstream datagrams are dropped before reaching upstreams.

## Compatibility

- Existing UDP beta configs continue to load; the new fields have bounded
  defaults.
- `udp-proxy` is still not part of the normal release profiles.
