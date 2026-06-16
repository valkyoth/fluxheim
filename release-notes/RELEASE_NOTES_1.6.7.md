# Fluxheim 1.6.7 Release Notes

Fluxheim 1.6.7 starts the server-bootstrap cutover in the 1.6 Pingora-exit line. The active HTTP runtime still uses Pingora for this slice, but the listener inventory and process bootstrap settings now flow through Fluxheim-owned server plan types.

## Changed

- Added config-to-`ServerPlan` construction in `fluxheim-server`.
- Moved HTTP, HTTPS, admin, metrics, stream, and UDP listener inventory into the Fluxheim server plan boundary.
- Moved daemon mode, PID/upgrade/certificate-reload socket paths, worker/thread settings, keepalive pool sizing, retry count, and graceful shutdown timing into the Fluxheim process plan boundary.
- Updated the root runtime Pingora adapter to consume the Fluxheim server plan for process configuration and HTTP, HTTPS, admin, and metrics listener registration.
- Updated root background-service registration gates to consume Fluxheim server-plan task metadata for cache purging, cache metrics, OTLP metrics export, ACME renewal, and certificate reload control.
- Added Fluxheim-owned foreground service intent metadata for proxy, admin, ops socket, metrics, stream proxy, and UDP proxy service registration.
- Added an explicit server-plan runtime adapter marker so the current Pingora compatibility runtime is a named adapter boundary before the native server cutover.
- Added server-plan listener lookup helpers so runtime/admin adapters consume HTTP, HTTPS, admin, and metrics listener addresses through `fluxheim-server`.
- Removed duplicated downstream TLS listener-address storage from `fluxheim-tls`; HTTPS listener addresses now come from the server plan while TLS planning owns certificate selection and policy.
- Moved downstream PROXY protocol listener policy and trusted-source parsing into `fluxheim-server`, leaving the root runtime as a Pingora listener-policy adapter.
- Split `fluxheim-server` process planning and PROXY protocol planning into focused modules so the new server crate stays under the 500-line modularity target.
- Moved private Unix listener creation for the certificate reload control socket into `fluxheim-server`, including stale socket replacement, mode `0600`, and nonblocking setup.
- Split server listener and foreground service inventory types into focused `fluxheim-server` modules before the native bootstrap work adds more runtime state.
- Moved downstream HTTP/2 hardening limits into a Pingora-neutral `fluxheim-server` policy plan, with the root runtime only adapting those values into Pingora `H2Options`.
- Moved certificate reload control socket policy into `fluxheim-server` so the socket path, concurrency cap, and request read timeout are planned outside the Pingora runtime adapter.
- Added server-plan lookup helpers for foreground services and background tasks, then made the root runtime adapter consume planned names when registering services.
- Added load-balancer health-check service intent to `ServerPlan` so load-balancer foreground registration is planned alongside proxy, admin, metrics, stream, and UDP services.
- Split server service-intent and background-task intent detection into focused `fluxheim-server` modules, reducing the server crate root while preserving the same runtime plan.
- Split listener inventory construction into the `fluxheim-server` listener module, keeping HTTP, HTTPS, admin, metrics, stream, and UDP listener parsing out of the server crate root.
- Moved certificate reload control-plan construction into the focused `fluxheim-server` control module beside the control socket policy type.
- Added listener-protocol ownership to foreground service specs so the server plan can map proxy, admin, metrics, stream, and UDP services back to their planned listeners.
- Updated the admin and metrics runtime adapters to consume service-owned listener lookups from the server plan.
- Added protocol-filtered service listener lookup and moved proxy HTTP/HTTPS listener registration onto the service-owned lookup path.
- Added a background-service adapter helper that consumes planned `BackgroundTaskSpec` values directly, removing duplicated task kind/name wiring from plan-driven runtime services.
- Updated admin service construction to consume planned control-plane and ops-socket service names from `ServerPlan`.
- Converted the admin self-healing watchdog registration to the typed background task spec path and removed the old name/kind free helper.
- Added admin self-healing watchdog intent to `ServerPlan` so the admin adapter consumes the planned `RuntimeWatchdog` task instead of creating it locally.
- Split the `ServerPlan` implementation into a focused `fluxheim-server` plan module, leaving the crate root as the public export and error surface.
- Added an admin ops-socket endpoint plan to `ServerPlan` and updated the admin adapter to consume planned socket path and mode values.
- Added a first-service-listener lookup to `ServerPlan` and updated admin service construction/logging to use the planned admin listener.
- Added borrow-based service listener iterators to `ServerPlan`, keeping the allocation-based address helpers as adapter conveniences.
- Updated proxy HTTP and metrics listener registration to consume the borrow-based service listener views directly before adapting into Pingora.
- Hardened private Unix listener setup by binding under a temporary private umask, using fd-based `fchmod` after bind, and using `rustix` path operations for stale socket cleanup.
- Removed the duplicate admin ops-socket mode parser from `fluxheim-server`; server planning now delegates to the validated config accessor.
- Documented that `ListenerSpec::proxy_protocol_enabled()` reports only the server-level HTTP/HTTPS downstream PROXY protocol policy.

## Tests

- Added focused `fluxheim-server` tests for listener inventory, background-task intent, invalid listener handling, public-listener detection, and server-runner shutdown behavior.
- Updated root runtime tests so Pingora `ServerConf` mapping is exercised through `fluxheim-server`.
- Added a live admin-listener smoke test that starts Fluxheim, reaches the normal HTTP listener, checks unauthenticated admin health, checks authenticated admin status, and checks the local read-only ops socket.
- Verified plan-gated foreground service registration with live admin, observability, stream proxy, and UDP proxy smokes.
- Kept the new server crate files below the 500-line modularity target by splitting tests into `server_tests.rs`, `listener.rs`, `service.rs`, `process.rs`, and `proxy_protocol.rs`.
- Added a `fluxheim-server` regression test proving private Unix listener paths replace stale sockets, reject non-socket files, and enforce private permissions.
- Added a `fluxheim-server` regression test for the downstream HTTP/2 hardening defaults consumed by the runtime adapter.
- Added a `fluxheim-server` regression test for the certificate reload control socket plan and kept the live admin listener smoke in the verification set.
- Extended `fluxheim-server` tests to cover planned service and background-task lookup by kind.
- Added a `fluxheim-server` regression test for load-balancer service intent and verified the runtime path with the live load-balancer smoke.
- Kept the split server intent modules covered by `cargo test -p fluxheim-server` and the release-gated modularity policy check.
- Verified the listener-planning split with `cargo test -p fluxheim-server` and the live admin listener smoke.
- Split private Unix listener regression coverage into a focused Unix-only test module so the main server test module remains well below the 500-line target.
- Added `fluxheim-server` regression coverage for service-owned listener address lookup.
- Added `fluxheim-server` regression coverage for protocol-filtered service listener lookup.
- Extended `fluxheim-server` background-task inventory coverage to include the planned admin self-healing watchdog.
- Split server background-task inventory tests into a focused module so the main server test file stays comfortably below the 500-line target.
- Added `fluxheim-server` regression coverage for admin ops-socket path and mode planning.
- Added `fluxheim-server` regression coverage for first service-listener lookup.
- Added `fluxheim-server` regression coverage for service listener iterator views.
- Added `proxy,acme-client` runtime test coverage for disabled certificate reload control service planning.

## Verification

- `cargo test -p fluxheim-server`
- `cargo test -p fluxheim-tls`
- `RUSTFLAGS='-D warnings' cargo test --lib runtime::tests`
- `cargo test --no-default-features --features proxy,acme-client --lib runtime::tests`
- `RUSTFLAGS='-D warnings' cargo test --lib admin::tests::admin_services_enable_watchdog_only_when_self_healing_is_enabled`
- `RUSTFLAGS='-D warnings' cargo check --workspace`
- `scripts/validate-modularity-policy.sh check`
- `scripts/validate-pingora-dependency-policy.sh check`
- `scripts/validate-pingora-boundary-policy.sh check`
- `scripts/smoke_admin_listener.sh`
- `FLUXHEIM_SMOKE_SKIP_CORE_MATRIX=1 scripts/smoke_1_0_core.sh`
- `scripts/smoke_observability_local.sh`
- `scripts/smoke_stream_proxy.sh`
- `scripts/smoke_udp_proxy.sh`
- `scripts/stable_release_gate.sh`
- `scripts/podman_smoke.sh`
