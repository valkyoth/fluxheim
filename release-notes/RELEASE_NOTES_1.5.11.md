# Fluxheim 1.5.11 Release Notes

Fluxheim 1.5.11 starts the service-discovery and control-plane integration
line.

## Planned Scope

- Add one or more bounded discovery adapters such as Kubernetes, Consul, or
  xDS after local DNS/file discovery and runtime backend mutation are stable.
- Keep discovery changes inside clear authentication/trust boundaries, churn
  limits, safe fallback behavior, status visibility, audit/metrics events, and
  reload behavior.
- Do not add UDP/GSLB, WAF, VPN/firewall appliance behavior, or
  Wasm/iRules/Lua scripting in this release.

## Changed

- Updated Fluxheim and the vendored `pingora-core` metrics dependency from
  Prometheus 0.13 to Prometheus 0.14.
- Moved the transitive protobuf dependency from vulnerable 2.x to protobuf
  3.7.2 through the Prometheus update.
- Removed the obsolete `RUSTSEC-2024-0437` suppression from `cargo audit`,
  `cargo deny`, and release metadata validation.
- Kept Pingora pinned at `=0.8.0` so normal dependency refreshes cannot bypass
  Fluxheim's patched vendored Pingora core.
- Hardened downstream HTTP/2 defaults against the HTTP/2 Bomb class by capping
  decoded request header lists at 64 KiB per stream, capping remotely initiated
  concurrent streams at 32 per connection, and defaulting downstream write
  timeout to 30 seconds.
- Added bounded pull-based HTTP upstream discovery for load-balancer pools using
  `proxy.upstreams_http_url`, optional bearer-token authentication, 64 KiB
  response limits, 2-64 unique authority validation, and 1-300 second refresh
  intervals.

## Stop Line

This release does not add UDP/GSLB, WAF, VPN/firewall appliance behavior, or
Wasm/iRules/Lua scripting. HTTP discovery is pull-based and does not implement
native Kubernetes watches, Consul blocking queries, or xDS streams in this
release.
