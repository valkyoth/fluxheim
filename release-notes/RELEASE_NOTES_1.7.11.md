# Fluxheim 1.7.11 Release Notes

Fluxheim 1.7.11 delivers the zero-downtime process-upgrade slice after the
stable 1.7 Wasm policy milestones. It combines bounded native drain, strict
listener inheritance, readiness-gated handoff, and tested native and Podman
deployment patterns.

The release also completes the native HTTP/1 parser audit and tightens critical
background-service ownership without changing operator configuration defaults.

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
- Claim inherited systemd descriptors exactly once per process and own the
  complete set before validating any item. Concurrent calls and retries fail
  before touching FD 3, while validation failures close the complete set.

## Fixed

- Use one validated HTTP/1 authority for routing, authorization, forwarding,
  and cache partitioning. Conflicting absolute-form authority and `Host`,
  malformed ports/IPv6/host syntax, non-HTTP absolute targets, and malformed
  absolute URIs now fail before request dispatch.
- Reject every HTTP/1.0 `Transfer-Encoding` message before evaluating
  keep-alive. Chunked decoding now bounds encoded bytes, line length, extension
  bytes, and chunk count, validates extension grammar, streams decoded data into
  caller-owned output, and preserves identical parser results across every
  fragmented-read boundary, including a split terminal CRLF at the line limit.
- Return only a semantically validated public HTTP/1 request-head type. Host and
  authority agreement, request-target grammar, body framing, and persistence
  are resolved before callers can inspect or route a request.
- Enforce the RFC 3986 ASCII path/query grammar and reject malformed raw or
  percent-encoded target characters before routing.
- Reject origin response status codes outside `100..=599`, oversized PROXY v1
  lines, and PROXY v2 payloads that exceed policy or differ from the declared
  frame length.
- Prevent construction of unvalidated protocol headers, share one bounded
  `Connection` option parser with hop-by-hop filtering, and add dedicated fuzz
  targets for HTTP/1 request/response heads, request targets, chunk bodies, and
  PROXY v1/v2 frames.
- Route HTTP/2 requests exclusively by `:authority`; supplied `Host` fields are
  replaced and requests without authority fail closed.
- Remove all fixed and `Connection`-nominated hop-by-hop origin response
  headers before delivery or cache admission, and reject malformed options.
- Read through at most eight HTTP/1 informational origin responses to the final
  response, reject generic status 101, and reject transfer-coding chains that
  Fluxheim cannot decode completely.
- Prevent oversized embedded HTTP/1 connection limits from reaching Tokio's
  panicking semaphore constructor.
- Accept only ownership-checked critical task handles in the runtime watchdog.
  Attempted noncritical registration returns the original live handle instead
  of dropping it and cancelling cache, metrics, certificate, or maintenance
  services.
- Stop accepting caller-controlled executable and temporary-root paths in the
  zero-downtime and Podman blue/green smoke helpers. Their executable and
  secure workspace locations are now derived from fixed repository paths and
  Python-managed mode-`0700` temporary directories, resolving the associated
  CodeQL command/path alerts.
- Poll the final SWR disk-cache assertion for a bounded interval so the smoke
  observes the supported asynchronous memory-publish/disk-persistence order
  without masking a disk-store failure.

## Build And Packaging

- Pin the source, container build images, and RPM build prerequisite to the
  Rust 1.97 toolchain line.
- Include the disabled-by-default `fluxheim.socket` systemd unit in the RPM
  payload alongside the documented activation workflow.
- Update the interactive RPM build menu to Fedora 44 and openSUSE Leap 16.0,
  removing the end-of-life openSUSE Leap 15 target.
