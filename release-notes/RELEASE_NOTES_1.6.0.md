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
- Added `scripts/capture-runtime-performance-baseline.sh` and wired it into
  release-mode runtime baseline capture. It records local startup time, idle
  RSS/file descriptors, static HTTP latency, cache MISS/HIT latency,
  load-balancer route timing, keep-alive throughput, and fresh TLS connection
  timing.
- Added `docs/pingora-dependency-exceptions.tsv` and
  `scripts/validate-pingora-dependency-policy.sh` so the 1.6 line has a
  release-gated inventory of allowed Pingora crates per official profile.
- Added `docs/runtime-parity-fixtures.md`,
  `docs/runtime-parity-fixtures.tsv`, and
  `scripts/validate-runtime-fixtures.sh` to pin the smoke scripts, examples,
  and TLS fixtures that define runtime parity before HTTP/cache/LB/TLS
  cutovers begin.
- Added initial `fluxheim-runtime` and `fluxheim-server` workspace crates for
  Fluxheim-owned shutdown, background task, listener, and server-runner
  boundary traits. The current Pingora runtime path is unchanged.
- Added typed `PolicyEpoch`, `PolicyProof`, `RuntimeFact`, decision, reason,
  and visibility primitives in `fluxheim-runtime` for later policy-proof
  adoption. They are not wired into request handling in this release.
- Added `docs/extraction-dependency-graph.md` to record the intended split
  order for `snapshot`, protocol, tracing/observability, headers, ACME,
  runtime/server, cache, proxy, and admin modules before the Pingora cutover.
- Added the runtime-facts and policy-proofs planning model. The goal is typed,
  bounded, redacted evidence for Fluxheim decisions such as config promotion,
  route policy, cache admission, load-balancer selection, and admin mutation
  without putting a database in the request path.

## Changed

- Updated project version surfaces to `1.6.0`.
- Updated documentation language so the `1.5.x` line is treated as closed and
  future load-balancer health-check work is no longer described as a later
  `1.5.x` item.
- Refreshed `ROADMAP.md` so `1.6.x` is consistently documented as the
  Pingora-exit line, shared Wasm extensibility is moved to `1.7`, and HTTP/3
  remains after the runtime boundary is stable.
- Hardened `scripts/validate-pingora-dependency-policy.sh` so documented
  Pingora removal targets are enforced against the current Fluxheim version
  instead of acting as a set-membership inventory only.
- Tightened release-gate scripts by requiring modularity exceptions to be
  listed as structured table rows and by giving the UDP smoke negative
  assertion a longer observation window.

## Notes

- This is not yet a Pingora-removal release. It establishes the baseline,
  modularity gate, and security model for the staged 1.6.x migration.
- The legacy modularity exception inventory is intentionally large at the
  start of the line. The purpose is to make oversized files visible and reduce
  them release by release rather than hide the debt.
