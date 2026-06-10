# Fluxheim 1.5.16 Release Notes

Fluxheim 1.5.16 starts the UDP/GSLB exploration line.

This release adds the first reviewed boundary for UDP work: a separate beta
`[udp]` configuration namespace and an opt-in `udp-proxy` feature gate. It does
not turn TCP stream routes into mixed TCP/UDP routes and it does not ship a
production UDP listener yet.

## What Changed

- Added `udp-proxy` as a beta feature gate.
- Added `[udp]` with `enabled` and `routes` fields.
- Added `[[udp.routes]]` with bounded route mode, listeners, upstreams,
  optional weights, optional aliases, idle/session timeouts, datagram caps, and
  session caps.
- Added explicit route modes for future scoped UDP modules:
  `dns-load-balance`, `syslog-forward`, `quic-pass-through`, and `game-proxy`.
- Added config validation for duplicate route names, duplicate listeners,
  duplicate upstreams, invalid listener/upstream authorities, invalid timeout
  values, oversized datagrams, excessive session caps, and invalid
  weight/alias lists.
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

## Not Included

- No production UDP socket/listener runtime yet.
- No generic catchall UDP proxy.
- No authoritative DNS server or full GSLB control plane.
- No WAF, VPN/firewall appliance behavior, HTTP/3 ingress, or
  Wasm/iRules/Lua scripting in this release.

## Packaging Notes

- RPM and container production profiles remain on the existing full feature
  set and do not enable `udp-proxy`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
