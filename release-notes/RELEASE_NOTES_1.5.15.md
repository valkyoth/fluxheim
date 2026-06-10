# Fluxheim 1.5.15 Release Notes

Fluxheim 1.5.15 starts the database/protocol-aware health-check line.

This release adds bounded Redis `PING` and MySQL/MariaDB handshake active
health checks for load-balancer pools where TCP connect is not enough and an
HTTP/gRPC endpoint is not available.

## What Changed

- Added `protocol = "redis"` for `proxy.load_balance.health_check`.
- Redis checks open a bounded TCP connection to the selected backend, send one
  fixed RESP `PING` frame, and require a simple-string `+PONG` response.
- Added `protocol = "mysql"` for `proxy.load_balance.health_check`.
- MySQL checks open a bounded TCP connection to the selected backend, read one
  MySQL server greeting packet, and require a protocol-10 handshake without
  sending a login packet or SQL query.
- Redis and MySQL checks use `connect_timeout_secs` and `read_timeout_secs`,
  inherit the normal consecutive success/failure thresholds, and report their
  protocol in runtime status.
- Redis and MySQL checks reject HTTP/gRPC matchers, request headers, port
  overrides, connection reuse, host overrides, and parallel checking.
- Added `examples/load-balancer-redis-health.toml` as a validated Redis health
  probe example.
- Added `examples/load-balancer-mysql-health.toml` as a validated
  MySQL/MariaDB health probe example.
- Added `scripts/smoke_redis_health_check.sh`, an optional Podman smoke that
  starts Valkey, verifies Fluxheim increments Valkey's Redis `PING` command
  counter, then stops Valkey and checks that Fluxheim marks the backend
  unhealthy.
- Added `scripts/smoke_mysql_health_check.sh`, an optional Podman smoke that
  starts MariaDB, verifies Fluxheim increments MariaDB's unauthenticated
  handshake counter, then stops MariaDB and checks that Fluxheim marks the
  backend unhealthy.

## Compatibility

- Existing TCP/TLS, HTTP, gRPC, JSON, weighted degraded, and exec health checks
  remain compatible.
- Redis and MySQL checks are health probes only. They do not authenticate, run
  Redis commands beyond `PING`, send a MySQL login packet, inspect keys or
  schemas, execute queries, or make Fluxheim a database proxy.
- Redis TLS, MySQL TLS/authenticated readiness, PostgreSQL readiness,
  SMTP/LDAP send-expect, and authenticated agent checks remain future work.

## Packaging Notes

- RPM and container documentation are updated for `1.5.15`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
