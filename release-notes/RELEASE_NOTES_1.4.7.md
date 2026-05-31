# Fluxheim 1.4.7 Release Notes

Fluxheim 1.4.7 is planned as a TCP stream hardening follow-up to the 1.4.6
stream proxy foundation.

## Added

- True per-read stream idle timeout. `idle_timeout_secs` now resets whenever
  either direction transfers bytes.
- Optional `max_connection_secs` remains available as a separate wall-clock
  lifetime cap.
- Stream upstream TLS controls, including SNI, certificate/hostname
  verification policy, one alternative certificate name, route-local CA bundles,
  and upstream mTLS client certificate/key material for rustls, OpenSSL, and
  BoringSSL builds.
- Stream-local upstream selection policy for weighted TCP selection, safe
  aliases, drained upstream exclusion, and backup upstream connect fallback.
- Local stream smoke coverage for raw TCP forwarding, drained/backup fallback,
  upstream PROXY protocol v1 send, and downstream PROXY protocol v1 receive
  from trusted sources.
- Stream unit coverage for wall-clock lifetime caps and upstream PROXY
  protocol v2 framing.

## Planned Scope

- Additional release hardening from CI, CodeQL, and pentest feedback.

## Out Of Scope

- UDP proxying.
- DNS-specific UDP load balancing.
- HTTP cache, compression, auth subrequest, PHP, header mutation, or body
  policy on stream routes.
- TLS passthrough SNI routing.
- Combining stream `upstream_tls` with `upstream_proxy_protocol`; PROXY must be
  written before the TLS handshake and needs a dedicated pre-TLS connector.
- xDS/Kubernetes/Consul discovery.
- Wasm/Lua stream filters.
