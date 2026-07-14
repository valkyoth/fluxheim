# Fluxheim 1.7.11 Release Notes

Fluxheim 1.7.11 delivers the zero-downtime process-upgrade slice after the
stable 1.7 Wasm policy milestones. It combines bounded native drain, strict
listener inheritance, readiness-gated handoff, and tested native and Podman
deployment patterns.

## Added

- Track accepted native HTTP, HTTPS, HTTP/2, and Unix-listener connections so
  shutdown stops new accepts while established connections drain.
- Apply `server.process.grace_period_seconds` and
  `server.process.graceful_shutdown_timeout_seconds` in the native runtime.
- Add live regressions for keep-alive drain behavior and bounded shutdown.
- Add a real-binary `SIGTERM` smoke to the maintained native HTTP/1 gate and
  human test launcher.
- Document the native binary, systemd socket-activation, and Podman blue/green
  handoff boundaries before exposing upgrade automation.
- Adopt public HTTP/HTTPS TCP listeners from the standard systemd FD-3
  protocol, requiring a matching `LISTEN_PID`, bounded descriptor count, and
  exact one-for-one launch-plan address match.
- Add unit coverage for malformed activation metadata and real-socket adoption,
  plus a real-binary smoke that serves through an inherited listener and proves
  malformed activation fails closed.
- Report systemd readiness only after native listener/background-service startup
  completes, fail startup if a configured notification socket is unreachable,
  and report bounded-drain status after a shutdown signal.
- Exercise an old and new Fluxheim process on one parent-owned listener. The
  maintained smoke proves a bad replacement leaves old serving, green readiness
  precedes drain, established old traffic completes, and new requests have no
  connection-refusal window.
- Ship an optional RPM/systemd socket unit for the packaged port-80 listener.
  It remains disabled by default so existing direct-binding deployments do not
  change behavior during package installation.
- Add a real rootless-Podman blue/green smoke. It verifies that direct published
  ports cannot be atomically replaced, then proves the supported stable-front
  pattern with failed-green rollback and old keep-alive drain.
- Wait for every configured background service to reach its explicit ready
  point before systemd receives `READY=1`; a service that exits first makes the
  replacement fail closed and leaves the old generation serving.
- Reject inherited descriptors that are not listening TCP sockets, including a
  live regression using a connected stream bound to the expected address.
- Defer public/admin accept loops until background readiness succeeds, and add
  a live late-failure replacement test proving the old generation serves every
  request while the replacement aborts.
- Explicitly abort outstanding listener and background tasks at the drain
  timeout instead of relying on whole-process teardown.
- Remove `listenfd` from socket activation and receive descriptors through a
  focused Fluxheim crate with environment clearing disabled, preserving memory
  safety for multithreaded and embedded runtimes.
