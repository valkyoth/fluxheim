# Fluxheim 1.6.0 Release Notes

Fluxheim 1.6.0 starts the Pingora-exit foundation line. This release is the
baseline and guardrail release for the 1.6 series; runtime behavior is intended
to remain unchanged while the project records the evidence and policy needed to
remove Pingora safely in later 1.6.x releases.

## Added

- Added the first 1.6 modularity policy and legacy exception inventory. New or
  newly split Rust implementation files should target 300 lines and stay under
  500 lines; existing oversized files are tracked explicitly so the exception
  list can shrink across the Pingora-exit line.
- Added `scripts/validate-modularity-policy.sh` to report and validate the
  current oversized Rust-file inventory against
  `docs/modularity-exceptions.md`.
- Added `docs/runtime-baseline.md` and
  `scripts/capture-runtime-baseline.sh` to record locked dependency trees,
  per-profile Pingora dependency presence, release metadata, and default
  release-binary size before the runtime cutover work begins.
- Added initial `fluxheim-runtime` and `fluxheim-server` workspace crates for
  Fluxheim-owned shutdown, background task, listener, and server-runner
  boundary traits. The current Pingora runtime path is unchanged.
- Added the runtime-facts and policy-proofs planning model. The goal is typed,
  bounded, redacted evidence for Fluxheim decisions such as config promotion,
  route policy, cache admission, load-balancer selection, and admin mutation
  without putting a database in the request path.

## Changed

- Updated project version surfaces to `1.6.0`.
- Updated documentation language so the `1.5.x` line is treated as closed and
  future load-balancer health-check work is no longer described as a later
  `1.5.x` item.

## Notes

- This is not yet a Pingora-removal release. It establishes the baseline,
  modularity gate, and security model for the staged 1.6.x migration.
- The legacy modularity exception inventory is intentionally large at the
  start of the line. The purpose is to make oversized files visible and reduce
  them release by release rather than hide the debt.
