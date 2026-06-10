# Fluxheim 1.5.15 Release Notes

Fluxheim 1.5.15 starts the database/protocol-aware health-check line.

This release adds bounded Redis `PING`, MySQL/MariaDB handshake, and
PostgreSQL SSLRequest active health checks for load-balancer pools where TCP
connect is not enough and an HTTP/gRPC endpoint is not available.

## What Changed

- Added `protocol = "redis"` for `proxy.load_balance.health_check`.
- Redis checks open a bounded TCP connection to the selected backend, send one
  fixed RESP `PING` frame, and require a simple-string `+PONG` response.
- Redis checks now read until CRLF within the existing 64-byte response cap, so
  fragmented `+PONG\r\n` responses do not falsely mark healthy Redis backends
  down.
- Added `protocol = "mysql"` for `proxy.load_balance.health_check`.
- MySQL checks open a bounded TCP connection to the selected backend, read one
  MySQL server greeting packet, and require a protocol-10 handshake without
  sending a login packet or SQL query.
- Added `protocol = "postgres"` for `proxy.load_balance.health_check`.
- PostgreSQL checks open a bounded TCP connection to the selected backend, send
  the PostgreSQL SSLRequest pre-auth handshake, and require a one-byte `S` or
  `N` response without sending a StartupMessage or SQL query.
- Redis, MySQL, and PostgreSQL checks use `connect_timeout_secs` and
  `read_timeout_secs`, inherit the normal consecutive success/failure
  thresholds, and report their protocol in runtime status.
- Redis, MySQL, and PostgreSQL checks reject HTTP/gRPC matchers, request
  headers, port overrides, connection reuse, host overrides, and parallel
  checking.
- Added `examples/load-balancer-redis-health.toml` as a validated Redis health
  probe example.
- Added `examples/load-balancer-mysql-health.toml` as a validated
  MySQL/MariaDB health probe example.
- Added `examples/load-balancer-postgres-health.toml` as a validated
  PostgreSQL health probe example.
- Added `scripts/smoke_redis_health_check.sh`, an optional Podman smoke that
  starts Valkey, verifies Fluxheim increments Valkey's Redis `PING` command
  counter, then stops Valkey and checks that Fluxheim marks the backend
  unhealthy.
- Added `scripts/smoke_mysql_health_check.sh`, an optional Podman smoke that
  starts MariaDB, verifies Fluxheim increments MariaDB's unauthenticated
  handshake counter, then stops MariaDB and checks that Fluxheim marks the
  backend unhealthy.
- Added `scripts/smoke_postgres_health_check.sh`, an optional Podman smoke that
  starts PostgreSQL, verifies Fluxheim creates a pre-auth connection observed
  by PostgreSQL connection logging, then stops PostgreSQL and checks that
  Fluxheim marks the backend unhealthy.

## Compatibility

- Existing TCP/TLS, HTTP, gRPC, JSON, weighted degraded, and exec health checks
  remain compatible.
- Redis, MySQL, and PostgreSQL checks are health probes only. They do not
  authenticate, run Redis commands beyond `PING`, send MySQL login packets,
  send PostgreSQL StartupMessages, inspect keys or schemas, execute queries, or
  make Fluxheim a database proxy.
- The MySQL/MariaDB probe intentionally disconnects before authentication. On
  non-loopback database connections, repeated idle probes can count toward the
  server host-cache error budget (`max_connect_errors`) and block the Fluxheim
  host until `FLUSH HOSTS` or equivalent cleanup. Use conservative intervals,
  raise `max_connect_errors`, or use an authenticated `exec` check such as
  `mysqladmin ping` for credentialed readiness.
- ACME managed-certificate install recovery now logs cleanup and backup-restore
  failures instead of silently discarding those errors.
- Delay-mode rate limiting and load-balancer persistence warning generation
  received small defensive hardening so local invariants are explicit at the
  panic-sensitive call sites.
- Redis TLS, MySQL TLS/authenticated readiness, PostgreSQL TLS/authenticated
  readiness, SMTP/LDAP send-expect, and authenticated agent checks remain
  future work.

## Packaging Notes

- RPM and container documentation are updated for `1.5.15`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
