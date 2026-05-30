# Fluxheim 1.4.6 Release Notes

Fluxheim 1.4.6 is planned as the TCP stream proxy foundation release.

## Planned Scope

- L4 TCP stream proxy basics with separate stream semantics.
- Port/listener-based stream routing to one or more upstreams.
- Bounded bidirectional byte copy with timeout and connection limits.
- Stream metrics for connection outcomes and byte counters.
- Upstream PROXY protocol send where configured.
- Optional upstream TLS and upstream mTLS only if the implementation can reuse
  the existing safe certificate/key loading model.

## Out Of Scope

- UDP proxying.
- DNS-specific UDP load balancing.
- HTTP cache, compression, auth subrequest, PHP, or header policy on stream
  routes.
- TLS passthrough SNI routing.
- xDS/Kubernetes/Consul service discovery.
- Wasm/Lua stream filters.
