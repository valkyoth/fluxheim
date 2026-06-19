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
- Split native HTTP/1.1 and gRPC/h2 health-check helper code into focused
  private modules under `fluxheim-load-balancer`. This keeps the protocol
  serialization/parsing paths reviewable without changing the public
  load-balancer API.
- Split Redis, MySQL, and PostgreSQL active health probes into a private
  database health module. The wire-format parsers, request constants, and
  timeout handling remain unchanged, but database probe review no longer shares
  a large file with HTTP/gRPC orchestration.

## Compatibility

- The root compatibility runtime may still compile Pingora while this release
  is in progress. The release target is to remove Pingora proxy/cache/pool
  crates from normal official profiles only when the native replacement paths
  pass the same release gates and smoke tests.
