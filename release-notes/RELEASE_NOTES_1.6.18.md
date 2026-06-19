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

## Compatibility

- The root compatibility runtime may still compile Pingora while this release
  is in progress. The release target is to remove Pingora proxy/cache/pool
  crates from normal official profiles only when the native replacement paths
  pass the same release gates and smoke tests.
