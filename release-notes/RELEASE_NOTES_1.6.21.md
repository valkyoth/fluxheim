# Fluxheim 1.6.21 Release Notes

Fluxheim 1.6.21 continues the staged Pingora-exit line by moving internal
background task orchestration toward Fluxheim-owned runtime supervision while
keeping production listener behavior conservative.

## Changed

- Start the native background-service orchestration slice for certificate
  reload, ACME renewal, cache maintenance, observability export, and
  load-balancer refresh tasks.
- Add `fluxheim_runtime::NativeBackgroundSupervisor` for Pingora-free
  background service spawning, readiness callbacks, shutdown fan-out, and
  join/abort supervision.
- Keep the final Pingora-free proof target at 1.6.24 while this release focuses
  on task-supervision boundaries rather than listener/runtime replacement.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.21`.

## Security

- Preserve the `pingora-compat` runtime boundary and dependency-policy gates
  while adding the Fluxheim-owned supervision primitive that internal
  background tasks will use during the remaining runtime/listener cutover.
- Add native critical background-task watchdog support so critical task exits can
  trigger supervisor shutdown before production task wiring moves off Pingora.
- Fix native supervisor shutdown delivery for pre-spawn shutdown, last-handle
  drop, and clone-drop edge cases.
- Harden the native runtime cutover evidence script against unsafe TOML path
  interpolation and missing expected blocker rows in the representative report.
- Mark background-service `threads()` as Pingora compatibility-only; the native
  supervisor does not treat it as a per-service thread-pool contract.
- Keep the first-party `zeroize` to `sanitization` migration planned for the
  post-Pingora stabilization release so secret-container API changes are tested
  as a focused hardening pass.

## Compatibility Boundary

- Normal proxy profiles still retain the Pingora compatibility runtime in this
  release. The goal of 1.6.21 is to shrink internal task orchestration
  dependency, not to flip production traffic to a new runtime in one step.
