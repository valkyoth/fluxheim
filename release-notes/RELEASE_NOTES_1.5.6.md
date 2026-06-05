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
- Replace the internal stream connection return type with a Fluxheim-owned
  async IO boundary. Plain TCP stream upstreams now stay as Tokio `TcpStream`
  values instead of being wrapped in Pingora's L4 stream type; TLS upstreams are
  adapted behind the same internal boundary.
- Isolate stream upstream TLS connector setup in a dedicated `stream_tls`
  adapter module. This keeps Pingora `TransportConnector` / `HttpPeer` wiring
  out of the stream proxy orchestration file.
- Replace the stream upstream TLS connector adapter with Fluxheim-native
  `tokio-rustls` / `tokio-openssl` connectors. Stream routes now use
  Fluxheim-owned TCP connect, TLS handshake, route-local trust roots, SNI
  derivation, verification policy, and upstream mTLS client material loading.

## Boundaries

1.5.6 preserves the existing stream route configuration, TCP stream proxy
behavior, route-local downstream and upstream PROXY protocol behavior, weighted
upstream selection, idle/lifetime/byte caps, metrics, release profiles, and
smoke-test shape. The stream listener, stream copy/proxy path, and stream
upstream TLS connector are Fluxheim-owned in this release line; stream routes
no longer require Pingora's listening service, stream wrapper, or TLS connector
adapter.

1.5.6 does not replace the HTTP proxy runtime, native load-balancer internals,
restart-persistent load-balancer state, active-active state sync, UDP/GSLB,
HTTP/3/QUIC, WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua
scripting.
