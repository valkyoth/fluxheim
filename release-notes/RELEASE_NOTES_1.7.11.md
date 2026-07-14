# Fluxheim 1.7.11 Release Notes

Fluxheim 1.7.11 starts the zero-downtime process-upgrade line after the stable
1.7 Wasm policy milestones. The first implementation slice establishes real,
bounded drain semantics before listener file-descriptor handoff and systemd
socket activation are enabled.

## In Progress

- Track accepted native HTTP, HTTPS, HTTP/2, and Unix-listener connections so
  shutdown stops new accepts while established connections drain.
- Apply `server.process.grace_period_seconds` and
  `server.process.graceful_shutdown_timeout_seconds` in the native runtime.
- Add live regressions for keep-alive drain behavior and bounded shutdown.
- Add a real-binary `SIGTERM` smoke to the maintained native HTTP/1 gate and
  human test launcher.
- Document the native binary, systemd socket-activation, and Podman blue/green
  handoff boundaries before exposing upgrade automation.
