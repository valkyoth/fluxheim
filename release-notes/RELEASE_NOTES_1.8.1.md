# Fluxheim 1.8.1 Release Notes

Fluxheim 1.8.1 expands the unsigned macOS portable line from its initial
archive baseline toward native runtime parity on Apple Silicon and Intel.

This release is under development.

## Native macOS Archives

- Run the macOS portable gate on native Apple Silicon and Intel GitHub-hosted
  runners.
- Build matching `.tar.gz` and `.zip` archives for the `full`, `wasm`, `cache`,
  `proxy`, `load-balancer`, `php`, and `config-tester` profiles on both
  architectures.
- Execute the packaged Wasm policy examples from the staged Wasm archive on
  each native architecture.

## Native Runtime Evidence

- Add one native macOS orchestrator for live static and proxy serving,
  downstream TLS, verified upstream TLS, local static and proxy cache, admin
  operations, load balancing, and local metrics/exporter health.
- Add an independently runnable verified-upstream-TLS smoke that creates a
  temporary private CA and requires certificate and hostname verification.
- Retain external Prometheus and Jaeger collector integration in the Linux
  release gate so the macOS portable gate does not depend on a container
  runtime.
- Make the packaged Wasm smoke portable across GNU `sha256sum` and macOS
  `shasum`.

## Deployment Boundary

Fluxheim supports foreground operation under an operator-selected supervisor;
it does not yet ship a supported launchd service definition. The macOS guide
documents APFS case behavior, POSIX ownership/mode and symlink checks, the
extended-ACL operator boundary, and the local-filesystem locking requirement.

These archives remain unsigned and are not notarized. SHA-256 checksums prove
artifact integrity against release metadata but do not establish publisher
identity.
