# Fluxheim 1.6.20 Release Notes

Fluxheim 1.6.20 starts the final Pingora runtime-removal phase by making the
remaining production cutover blockers explicit and moving the dependency policy
to a truthful multi-release exit plan.

## Changed

- Re-scope the remaining Pingora-exit plan into focused runtime slices instead
  of forcing a single unsafe cutover. The final normal-build Pingora-free proof
  target is now 1.6.24, after native background task orchestration, admin and
  metrics serving, stream/UDP listener startup, and HTTP runtime compatibility
  gaps are closed with tests.
- Keep `1.6.20` focused on the native runtime cutover contract: native TLS and
  listener proof builds stay Pingora-free, while the remaining production
  compatibility adapter is retained only where the tested native path still has
  blockers.
- Move Pingora dependency exception targets from `1.6.20` to `1.6.24` with the
  roadmap updated in the same release. This is not a relaxation of the policy:
  the gate remains active and will fail if Pingora appears outside the listed
  profiles or survives beyond the final proof target.
- Update release metadata and container tag documentation for `v1.6.20`.

## Security

- Preserve the explicit `pingora-compat` boundary introduced in 1.6.19 while
  preventing a misleading final-cutover claim before native admin, metrics,
  stream, UDP, and production HTTP runtime coverage are complete.
- Keep the dependency-policy gate enforcing every remaining Pingora crate by
  profile and removal target. New Pingora edges outside the documented
  compatibility surface remain release-blocking.

## Compatibility Boundary

- Normal proxy profiles still use the Pingora compatibility runtime in this
  release. The 1.6.20 change is planning and evidence hardening for the final
  cutover, not a production runtime switch.
- Native web TLS proof profiles remain Pingora-free and continue to be covered
  by release gates.
