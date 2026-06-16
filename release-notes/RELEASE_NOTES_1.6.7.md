# Fluxheim 1.6.7 Release Notes

Fluxheim 1.6.7 starts the server-bootstrap cutover in the 1.6 Pingora-exit line. The active HTTP runtime still uses Pingora for this slice, but the listener inventory and process bootstrap settings now flow through Fluxheim-owned server plan types.

## Changed

- Added config-to-`ServerPlan` construction in `fluxheim-server`.
- Moved HTTP, HTTPS, admin, metrics, stream, and UDP listener inventory into the Fluxheim server plan boundary.
- Moved daemon mode, PID/upgrade/certificate-reload socket paths, worker/thread settings, keepalive pool sizing, retry count, and graceful shutdown timing into the Fluxheim process plan boundary.
- Updated the root runtime Pingora adapter to consume the Fluxheim server plan for process configuration and HTTP, HTTPS, admin, and metrics listener registration.
- Updated root background-service registration gates to consume Fluxheim server-plan task metadata for cache purging, cache metrics, OTLP metrics export, ACME renewal, and certificate reload control.
- Added Fluxheim-owned foreground service intent metadata for proxy, admin, ops socket, metrics, stream proxy, and UDP proxy service registration.

## Tests

- Added focused `fluxheim-server` tests for listener inventory, background-task intent, invalid listener handling, public-listener detection, and server-runner shutdown behavior.
- Updated root runtime tests so Pingora `ServerConf` mapping is exercised through `fluxheim-server`.
- Added a live admin-listener smoke test that starts Fluxheim, reaches the normal HTTP listener, checks unauthenticated admin health, checks authenticated admin status, and checks the local read-only ops socket.
- Verified plan-gated foreground service registration with live admin, observability, stream proxy, and UDP proxy smokes.
- Kept the new server crate files below the 500-line modularity target by splitting tests into `server_tests.rs`.

## Verification

- `cargo test -p fluxheim-server`
- `RUSTFLAGS='-D warnings' cargo test --lib runtime::tests`
- `RUSTFLAGS='-D warnings' cargo test --lib admin::tests::admin_services_enable_watchdog_only_when_self_healing_is_enabled`
- `RUSTFLAGS='-D warnings' cargo check --workspace`
- `scripts/validate-modularity-policy.sh check`
- `scripts/smoke_admin_listener.sh`
- `FLUXHEIM_SMOKE_SKIP_CORE_MATRIX=1 scripts/smoke_1_0_core.sh`
- `scripts/smoke_observability_local.sh`
- `scripts/smoke_stream_proxy.sh`
- `scripts/smoke_udp_proxy.sh`
