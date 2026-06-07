# Fluxheim 1.5.8 Release Notes

Fluxheim 1.5.8 expands active health checks for production load-balanced pools:
custom request headers, standard gRPC health checks, exact JSON scalar body
checks, and health-derived degraded weights.

## Added

- HTTP and gRPC active health checks can now send configured request headers:

```toml
[proxy.load_balance.health_check]
protocol = "http"
path = "/healthz"

[[proxy.load_balance.health_check.request_headers]]
name = "Authorization"
  value = "Bearer health-check-token"
```
- `protocol = "grpc"` runs the standard gRPC Health Checking Protocol over
  HTTP/2. `grpc_service = "package.Service"` optionally checks a specific
  service name.
- `expected_body_json` validates exact scalar JSON health fields with bounded
  dot-separated object paths.
- `X-Health-Weight: N` on a successful HTTP or gRPC health response lowers the
  backend's effective selection weight to `N` percent while it remains healthy.
  `100` or an absent header clears the health-derived override.

## Security And Bounds

- `request_headers` is valid only for HTTP and gRPC health checks.
- At most 16 request headers may be configured.
- Header values are capped at 1024 bytes.
- Duplicate header names are rejected case-insensitively.
- `Host` is reserved for the existing `host` setting.
- Hop-by-hop and proxy-control headers such as `Connection`,
  `Transfer-Encoding`, `Upgrade`, and proxy auth headers are rejected.
- Header values are not emitted in load-balancer metrics labels or runtime
  status output.
- gRPC health checks use fixed standard request/response semantics and reject
  conflicting HTTP status/header/body matcher config.
- JSON health matchers are exact scalar checks only; no JSONPath, arrays,
  expressions, regexes, or scripts are evaluated.
- Health-derived weights are bounded to `1..=100`, stored separately from
  configured/admin runtime weights, pruned with backend state, and exposed in
  status as `health_weight_percent`.

## Stop Line

This release does not add exec checks, database protocol probes, runtime
backend add/remove, UDP/GSLB, WAF, VPN/firewall features, or Wasm/iRules/Lua
functionality. Those remain planned for later roadmap items.
