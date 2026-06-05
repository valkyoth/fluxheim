# Fluxheim 1.5.6 Release Notes

Fluxheim 1.5.6 starts the Fluxheim-native stream-proxy runtime line. The goal
is to move stream connect, copy, shutdown, and runtime-boundary helpers toward
owned Tokio/Fluxheim surfaces while preserving the shipped TCP stream proxy
configuration and behavior.

## Changed

- Start stream-proxy runtime ownership work for the `1.5.x` dependency-reduction
  line.
- Move stream connect, copy, shutdown, upstream resolution, upstream PROXY
  header writes, byte-limit enforcement, and lifetime/idle timeout helpers onto
  the internal `FluxError` / `FluxResult` surface.
- Make the stream copy/proxy data path generic over Tokio
  `AsyncRead + AsyncWrite` streams so the next listener/connector slice is not
  tied to Pingora's stream wrapper internally.
- Replace the stream proxy's Pingora `ServerApp` / listening-service entrypoint
  with a Fluxheim-owned Tokio listener loop registered in the existing process
  supervisor.
- Add Fluxheim-owned bounded downstream PROXY protocol v1/v2 receive parsing
  and trusted-source matching for stream routes.
- Move stream data-path tests off Pingora's stream wrapper and add parser
  regression coverage for downstream PROXY protocol and trusted CIDR matching.

## Boundaries

1.5.6 preserves the existing stream route configuration, TCP stream proxy
behavior, route-local downstream and upstream PROXY protocol behavior, weighted
upstream selection, idle/lifetime/byte caps, metrics, release profiles, and
smoke-test shape. The upstream TLS connector adapter remains the main
stream-specific Pingora wrapper still planned for this release line.

1.5.6 does not replace the HTTP proxy runtime, native load-balancer internals,
restart-persistent load-balancer state, active-active state sync, UDP/GSLB,
HTTP/3/QUIC, WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua
scripting.
