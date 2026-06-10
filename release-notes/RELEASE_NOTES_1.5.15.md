# Fluxheim 1.5.15 Release Notes

Fluxheim 1.5.15 starts the database/protocol-aware health-check line.

This release adds a bounded Redis `PING` active health check for load-balancer
pools where TCP connect is not enough and an HTTP/gRPC endpoint is not
available.

## What Changed

- Added `protocol = "redis"` for `proxy.load_balance.health_check`.
- Redis checks open a bounded TCP connection to the selected backend, send one
  fixed RESP `PING` frame, and require a simple-string `+PONG` response.
- Redis checks use `connect_timeout_secs` and `read_timeout_secs`, inherit the
  normal consecutive success/failure thresholds, and report the protocol as
  `redis` in runtime status.
- Redis checks reject HTTP/gRPC matchers, request headers, port overrides,
  connection reuse, host overrides, and parallel checking.
- Added `examples/load-balancer-redis-health.toml` as a validated Redis health
  probe example.

## Compatibility

- Existing TCP/TLS, HTTP, gRPC, JSON, weighted degraded, and exec health checks
  remain compatible.
- Redis checks are health probes only. They do not authenticate, run Redis
  commands beyond `PING`, inspect keys, execute queries, or make Fluxheim a
  Redis/database proxy.
- Redis TLS, PostgreSQL readiness, MySQL readiness, SMTP/LDAP send-expect, and
  authenticated agent checks remain future work.

## Packaging Notes

- RPM and container documentation are updated for `1.5.15`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
