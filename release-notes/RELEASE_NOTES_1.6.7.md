# Fluxheim 1.6.7 Release Notes

Fluxheim 1.6.7 starts the server-bootstrap cutover in the 1.6 Pingora-exit line. The active HTTP runtime still uses Pingora for this slice, but the listener inventory and process bootstrap settings now flow through Fluxheim-owned server plan types.

## Changed

- Added config-to-`ServerPlan` construction in `fluxheim-server`.
- Moved HTTP, HTTPS, admin, metrics, stream, and UDP listener inventory into the Fluxheim server plan boundary.
- Moved daemon mode, PID/upgrade socket paths, worker/thread settings, keepalive pool sizing, retry count, and graceful shutdown timing into the Fluxheim process plan boundary.
- Updated the root runtime Pingora adapter to consume the Fluxheim server plan for process configuration and HTTP/metrics listener registration.

## Tests

- Added focused `fluxheim-server` tests for listener inventory, background-task intent, invalid listener handling, public-listener detection, and server-runner shutdown behavior.
- Updated root runtime tests so Pingora `ServerConf` mapping is exercised through `fluxheim-server`.
- Kept the new server crate files below the 500-line modularity target by splitting tests into `server_tests.rs`.

## Verification

- `cargo test -p fluxheim-server`
- `RUSTFLAGS='-D warnings' cargo test --lib runtime::tests`
- `RUSTFLAGS='-D warnings' cargo check --workspace`
- `scripts/validate-modularity-policy.sh check`
