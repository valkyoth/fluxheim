# Fluxheim 1.9.0 Release Notes

**Status: unreleased development draft.** `main` reports 1.9.0 to distinguish
it from the latest published release, v1.8.2. There is no 1.9.0 release tag,
published archive, or production HTTP/3 listener yet.

## Implemented In Commit 1

- Source-lock an isolated Quinn/rustls/h3 feasibility workspace. Exercise
  verified loopback HTTP/3 streaming and trailers, explicit crypto-provider
  selection, and address-change/reconnect behavior without adding QUIC to
  Fluxheim's runtime dependency graph.
- Add machine-checked scope, dependency, feature and implementation-ownership
  contracts, with negative regression coverage and CI integration.
- Record future Brynja replacement interfaces and capability gaps. Brynja
  remains future-only and is not a dependency or selectable backend.
- Refresh Rust to 1.99.0, stable Cargo dependencies, digest-pinned Rust builder
  images and Docker GitHub Actions. Update workspace and RPM development
  versions together. Existing runtime feature profiles remain unchanged.
- Use Rust 1.99's replacement atomic update API for UDP session admission,
  preserving the existing ordering and session-limit behavior.

## Qualification Still Required

Follow the [HTTP/3 commit plan](../docs/http3-quic-commit-plan.md). Commit 1 is a
candidate, not an accepted checkpoint: seamless NAT rebinding and active client
migration are selected requirements, but source qualification of safe path and
policy hooks remains pending, followed by pentest/retest and GitHub green.
Reconnect-only behavior is not an acceptable substitute. Later checkpoints
implement the listener, shared request/response
integration, packaging, and real-client/container/native-platform acceptance.

Current source and local test evidence is in the
[source contract](../docs/http3-source-contract.md). Successful dependency
probes are not evidence that a packaged Fluxheim binary serves HTTP/3.
