# Fluxheim 1.5.16 Release Notes

Fluxheim 1.5.16 starts the UDP/GSLB exploration line.

This release adds the first reviewed boundary for UDP work: a separate beta
`[udp]` configuration namespace, an opt-in `udp-proxy` feature gate, and a
small scoped UDP runtime for DNS-style request/response forwarding and
syslog-style one-way forwarding. It does not turn TCP stream routes into mixed
TCP/UDP routes and it does not ship production UDP/GSLB support yet.

## What Changed

- Added `udp-proxy` as a beta feature gate.
- Added `[udp]` with `enabled` and `routes` fields.
- Added `[[udp.routes]]` with bounded route mode, listeners, upstreams,
  optional weights, optional aliases, idle/session timeouts, datagram caps, and
  session caps. `max_sessions` defaults to `4096`; `0` remains an explicit
  unlimited setting.
- Added beta UDP listener/runtime support for `dns-load-balance` and
  `syslog-forward`.
- Added explicit reserved route modes for future scoped UDP modules:
  `quic-pass-through` and `game-proxy`.
- Added config validation for duplicate route names, duplicate listeners,
  duplicate upstreams, invalid listener/upstream authorities, invalid timeout
  values, oversized datagrams, excessive session caps, and invalid
  weight/alias lists.
- Added unit coverage with real local UDP sockets for request/response and
  one-way forwarding behavior.
- Added `scripts/smoke_udp_proxy.sh`, an optional local smoke that starts
  Fluxheim with a UDP-only config and proves DNS-style response forwarding plus
  syslog-style one-way delivery.
- Refreshed low-risk dependency and workflow pins: `base64-ng` 1.0.8, `http`
  1.4.2, manifest `log` 0.4.32, and exact current GitHub Action tags for
  checkout and Docker image workflows. Pingora was intentionally left unchanged.
- Kept `udp-proxy` out of the normal `full`, `proxy`, `cache`, `php`, and
  `load-balancer` release profiles until the runtime data plane is added and
  reviewed.

## Compatibility

- Existing HTTP proxy, cache, TCP stream proxy, and load-balancer configs are
  unchanged.
- Configs that set `udp.enabled = true` fail with a clear
  `udp.enabled requires building Fluxheim with the udp-proxy feature` error in
  normal production builds.
- The UDP namespace is intentionally separate from `[stream]`; TCP stream
  routing remains TCP-only.
- UDP-only beta configs can validate without HTTP/TLS listeners when built
  with `udp-proxy`.

## Not Included

- No production UDP/GSLB support yet.
- No generic catchall UDP proxy.
- No authoritative DNS server or full GSLB control plane.
- No QUIC pass-through or game-server UDP session proxying yet.
- No WAF, VPN/firewall appliance behavior, HTTP/3 ingress, or
  Wasm/iRules/Lua scripting in this release.

## Packaging Notes

- RPM and container production profiles remain on the existing full feature
  set and do not enable `udp-proxy`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
