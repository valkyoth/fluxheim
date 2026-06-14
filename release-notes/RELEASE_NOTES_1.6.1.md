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
- Kept the `pingora-load-balancing` dependency exception active until the
  first load-balancer extraction patch lands, without removing the policy gate.
- Updated workspace, RPM, README, build documentation, and release notes to
  `1.6.1`.

## Notes

- This release opens the `1.6.1` development line. The planned implementation
  target remains load-balancer independence from `pingora-load-balancing`.
