# Fluxheim 1.6.1 Release Notes

Fluxheim 1.6.1 starts the first Pingora-exit implementation release after the
1.6.0 foundation tag. The first concrete fix is release infrastructure: focused
load-balancer container images are again part of normal tag builds for the
1.6.x line.

## Changed

- Fixed the container image workflow so the load-balancer image profile builds
  on normal tag pushes after `v1.5.x`, including `v1.6.x`.
- Kept the manual `include_load_balancer=true` override only for older or
  non-release manual dispatch refs.
- Removed `pingora-load-balancing` and `pingora-ketama` from full and
  load-balancer image profile dependency trees by moving backend-set storage to
  Fluxheim-native backend types.
- Replaced the Pingora TCP health-check adapter with a Fluxheim-owned TCP
  connector and rustls/OpenSSL TLS handshake paths.
- Added `scripts/smoke_load_balancer_container.sh` so release testing can build
  the focused load-balancer image and prove round-robin plus header persistence
  behavior through a real container, while also checking that
  `pingora-load-balancing` and `pingora-ketama` are absent from that profile's
  dependency tree.
- Updated workspace, RPM, README, build documentation, and release notes to
  `1.6.1`.

## Notes

- This release completes the active dependency cut from `pingora-load-balancing`.
  The `pingora` HTTP health-check connector and current server-service adapter
  remain scheduled for the later HTTP/runtime cutover releases in the 1.6 line.
