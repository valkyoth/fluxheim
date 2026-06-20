# Fluxheim 1.6.22 Release Notes

Fluxheim 1.6.22 starts the native admin and metrics serving slice of the
Pingora-exit line. The goal is to move control-plane HTTP behavior behind
Fluxheim-owned server primitives without weakening admin authentication or
changing production listener behavior prematurely.

## Changed

- Start native admin/metrics serving work for the control-plane side of the
  remaining runtime cutover.
- Keep production admin and metrics compatibility conservative while native
  handler parity tests are introduced.
- Mark config-derived admin, ops-socket, and metrics service plans native-ready
  after proving native HTTP/1 handler parity for admin auth and Prometheus text
  responses.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.22`.

## Security

- Preserve the auth-first admin contract as the required behavior for native
  admin/control-plane serving.
- Harden native background task handles so accidental handle drops abort tasks
  instead of silently detaching them, while documenting that aborting a watched
  critical handle triggers supervisor shutdown.
- Mark native supervisor shutdown results as `#[must_use]` so callers cannot
  silently ignore whether they initiated shutdown or joined an existing
  shutdown.
- Reject newline-bearing paths in native runtime cutover evidence generation
  before interpolating them into TOML fixtures.
- Document that native admin target matching intentionally uses raw,
  percent-encoded paths to avoid normalization-bypass regressions.
- Keep native runtime cutover evidence active for stream, UDP, HTTP/2, and
  final proxy-runtime blockers until those services are wired to native
  listeners.

## Compatibility Boundary

- Normal proxy profiles still retain the Pingora compatibility runtime in this
  release. The admin and metrics cutover is staged so response shape, auth, and
  local smoke behavior can be proven before flipping production service
  registration.
