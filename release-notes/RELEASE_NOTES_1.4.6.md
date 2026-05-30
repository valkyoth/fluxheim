# Fluxheim 1.4.6 Release Notes

Fluxheim 1.4.6 is the TCP stream proxy foundation release.

## Added

- New optional `stream-proxy` Cargo feature.
- New `[stream]` config domain with `[[stream.routes]]` raw TCP services.
- Port/listener-based stream routing to one or more `host:port` upstreams.
- Round-robin upstream selection for multi-upstream stream routes.
- Bounded bidirectional Tokio byte copy with connect timeout, wall-clock
  `max_connection_secs`, optional `max_connection_bytes` per-direction caps,
  and per-route concurrent connection limits.
- Per-connection debug logging with downstream/upstream byte counts and
  duration.
- Optional Prometheus metrics for stream connection outcomes and per-direction
  byte totals when `metrics` is compiled.
- Upstream PROXY protocol v1/v2 send where configured.
- Route-local listener-side PROXY protocol v1/v2 receive on stream services
  through `stream.routes.downstream_proxy_protocol` and route-local
  `stream.routes.trusted_proxies`.
- Dependency evidence tracking for transitive `RUSTSEC-2024-0388`
  (`derivative`) with a scheduled release-metadata review gate.

## Out Of Scope

- UDP proxying.
- DNS-specific UDP load balancing.
- HTTP cache, compression, auth subrequest, PHP, or header policy on stream
  routes.
- Generic HTTP load-balancer policy on stream routes.
- Stream upstream TLS/mTLS.
- TLS passthrough SNI routing.
- True per-read idle timeout; `max_connection_secs` is a lifetime cap.
- xDS/Kubernetes/Consul service discovery.
- Wasm/Lua stream filters.
