# Fluxheim 1.5.14 Release Notes

Fluxheim 1.5.14 starts the local exec health-check line.

This release adds a bounded opt-in command monitor for load-balancer active
health checks where TCP/TLS, HTTP, gRPC, and JSON checks are not enough.

## What Changed

- Added `protocol = "exec"` for `proxy.load_balance.health_check`.
- Added `exec_command`, `exec_args`, `exec_allowed_commands`, and
  `exec_timeout_secs`.
- Exec commands must be absolute paths and must appear exactly in the
  configured allow-list.
- Exec checks run without a shell, with inherited environment cleared, and with
  stdin/stdout/stderr connected to null devices.
- Fluxheim provides bounded backend context through:
  `FLUXHEIM_HEALTH_BACKEND_ADDR`, `FLUXHEIM_HEALTH_BACKEND_HOST`, and
  `FLUXHEIM_HEALTH_BACKEND_PORT`.
- Load-balancer runtime status now reports the active health-check protocol
  without exposing exec command paths or arguments.
- Added `examples/load-balancer-exec-health.toml` as a validated local command
  monitor example.

## Compatibility

- Existing TCP, HTTP, gRPC, JSON, and weighted degraded health checks remain
  compatible.
- Exec checks are opt-in and are rejected if mixed with HTTP/gRPC request or
  response matcher fields.
- Exec command paths and arguments are normal configuration fields. They are
  not exposed in runtime status, but operators should not put credentials in
  argv or allow-list entries.
- Agent checks and database protocol probes remain future work.

## Packaging Notes

- RPM and container documentation are updated for `1.5.14`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
