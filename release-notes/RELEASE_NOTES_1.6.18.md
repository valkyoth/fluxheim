# Fluxheim 1.6.18 Release Notes

Fluxheim 1.6.18 continues the Pingora-exit line. The goal for this release is
to expand the native cutover toward every official profile while preserving the
1.6.17 proof that the `fluxheim-load-balancer` crate itself remains
Pingora-free.

## Security and Correctness

- Start from the 1.6.17 native load-balancer health-check hardening baseline:
  HTTP/1.1 health probes reject CR/LF in request path and Host values, gRPC
  health probes release h2 flow-control capacity, and h2 driver tasks are
  aborted on all exit paths.
- Harden native health probes after the 1.6.18 split: gRPC health requests now
  guard frame-length conversion, reject `@` userinfo in configured health hosts,
  require `grpc-status: 0` trailers, and reject overlarge protobuf varints;
  HTTP/1.1 health responses now use an 8 KiB response-header cap; exec health
  checks re-enforce `exec_allowed_commands` at runtime.
- Split native HTTP/1.1 and gRPC/h2 health-check helper code into focused
  private modules under `fluxheim-load-balancer`. This keeps the protocol
  serialization/parsing paths reviewable without changing the public
  load-balancer API.
- Split Redis, MySQL, and PostgreSQL active health probes into a private
  database health module. The wire-format parsers, request constants, and
  timeout handling remain unchanged, but database probe review no longer shares
  a large file with HTTP/gRPC orchestration.
- Split exec active health checks into a private exec module so command launch,
  environment scrubbing, timeout handling, and exit-status interpretation have a
  smaller dedicated review surface.
- Split TCP health checks, TCP/TLS handshake setup, ALPN selection, and shared
  HTTP health-stream connection handling into a private transport module. The
  bounded handshake behavior from 1.6.17 remains covered by the same tests.

## Compatibility

- The root compatibility runtime may still compile Pingora while this release
  is in progress. The release target is to remove Pingora proxy/cache/pool
  crates from normal official profiles only when the native replacement paths
  pass the same release gates and smoke tests.
- Keep root-profile Pingora dependency exceptions targeted at 1.6.19 while
  1.6.18 finishes the load-balancer health split. The dedicated
  `fluxheim-load-balancer` crate remains covered by the stricter Pingora-free
  gate.
