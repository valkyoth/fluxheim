# Fluxheim 1.8.1 Release Notes

Fluxheim 1.8.1 expands the unsigned macOS portable line from its initial
archive baseline toward native runtime parity on Apple Silicon. Intel macOS is
not a supported release target.

## Native macOS Archives

- Run the macOS portable gate on a native Apple Silicon GitHub-hosted runner.
- Build matching `.tar.gz` and `.zip` payloads for the `full`, `wasm`, `cache`,
  `proxy`, `load-balancer`, `php`, and `config-tester` profiles for ARM64
  macOS, verify their equivalence, and publish only the `.tar.gz` CLI archives.
- Execute the packaged Wasm policy examples from the staged Wasm archive on
  Apple Silicon.

## Native Runtime Evidence

- Refresh compatible Rust dependencies, CI actions, container bases, and the
  pinned Rust 1.98 toolchain used across release evidence.
- Add one native macOS orchestrator for live static and proxy serving,
  downstream TLS, verified upstream TLS, local static and proxy cache, admin
  operations, load balancing, and local metrics/exporter health.
- Add an independently runnable verified-upstream-TLS smoke that creates a
  temporary private CA and requires certificate and hostname verification.
- Serve a deterministic marker from that temporary HTTPS origin so Linux and
  macOS validate identical proxy behavior without depending on
  platform-specific `openssl s_server` output.
- Retain external Prometheus and Jaeger collector integration in the Linux
  release gate so the macOS portable gate does not depend on a container
  runtime.
- Make the packaged Wasm smoke portable across GNU `sha256sum` and macOS
  `shasum`.
- Refresh the reviewed vendored `instant-acme` policy digests for the
  intentional `base64-ng 2.0.1` dependency update.
- Clarify static-certificate ACME companion output while keeping certificate
  and private-key paths out of diagnostics.
- Keep local admin and certificate-reload sockets at verified mode `0600`
  without relying on descriptor `fchmod`, allowing the native admin runtime to
  start on macOS where that socket operation returns `EINVAL`.

## Deployment Boundary

Fluxheim supports foreground operation under an operator-selected supervisor;
it does not yet ship a supported launchd service definition. The macOS guide
documents APFS case behavior, POSIX ownership/mode and symlink checks, the
extended-ACL operator boundary, and the local-filesystem locking requirement.

These archives remain unsigned and are not notarized. SHA-256 checksums prove
artifact integrity against release metadata but do not establish publisher
identity.

The public preview uses a terminal-oriented `.tar.gz` download, checksum,
extraction, and installation workflow. ZIP remains an internal payload check;
signed and notarized graphical installation remains later platform work.

## Diagnostic And Filesystem Hardening

- Remove stale reviewed-warning text for dependencies and exceptions that are
  no longer present in the current all-feature dependency and audit policy.
- ACME, TLS, cache-encryption, stream-proxy, load-balancer, and background-task
  diagnostics retain actionable status without disclosing configured
  certificate, private-key, socket, route, key-identifier, or trusted-network
  values.
- Storage-bin symlink inspection walks from an opened trusted root with
  descriptor-relative, no-follow operations instead of reopening assembled
  paths.
- Regression coverage exercises symlinked, missing, and non-directory
  storage-bin path components, along with descriptor-relative PHP-FPM process
  inspection and admitted ACME reload test paths.
- Document that storage-bin mutation assumes a dedicated Fluxheim UID/root
  boundary, and track lifetime-retained directory descriptors as additional
  hardening for an exceptionally hostile local actor.
