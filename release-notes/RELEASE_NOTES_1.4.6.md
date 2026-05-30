# Fluxheim 1.4.6 Release Notes

Fluxheim 1.4.6 is the TCP stream proxy foundation release.

## Added

- New optional `stream-proxy` Cargo feature.
- New `[stream]` config domain with `[[stream.routes]]` raw TCP services.
- Port/listener-based stream routing to one or more `host:port` upstreams.
- Round-robin upstream selection for multi-upstream stream routes.
- Bounded bidirectional Tokio byte copy with connect timeout, idle timeout, and
  per-route concurrent connection limits.
- Per-connection debug logging with downstream/upstream byte counts and
  duration.
- Optional Prometheus metrics for stream connection outcomes and per-direction
  byte totals when `metrics` is compiled.
- Upstream PROXY protocol v1/v2 send where configured.
- Trusted listener-side PROXY protocol v1/v2 receive on stream services through
  the existing `server.proxy_protocol` and `server.trusted_proxies` policy.

## Out Of Scope

- UDP proxying.
- DNS-specific UDP load balancing.
- HTTP cache, compression, auth subrequest, PHP, or header policy on stream
  routes.
- Generic HTTP load-balancer policy on stream routes.
- Stream upstream TLS/mTLS.
- TLS passthrough SNI routing.
- xDS/Kubernetes/Consul service discovery.
- Wasm/Lua stream filters.
