# Security Policy

Fluxheim is security-sensitive infrastructure. Treat dependency, TLS, cache, and
request-routing changes as high-risk until tested.

## Routine Checks

Run these regularly and before releases:

```bash
scripts/checks.sh
scripts/release_checks.sh
cargo deny check
cargo deny check licenses
cargo audit
scripts/generate-sbom.sh
scripts/reproducible_build_check.sh
```

GitHub Actions run CI, and GitHub CodeQL default setup should be enabled in the
repository security settings. Keep only one active CodeQL configuration:
GitHub rejects SARIF uploads when default setup and an advanced workflow both
try to analyze the same repository.

The full release gate is documented in
[Release Checklist](docs/release-checklist.md). Use it before publishing
artifacts, changing dependency versions, or changing TLS/cache/proxy behavior.
The Rust dependency threat model and review rules are documented in
[Rust Supply-Chain Security](docs/supply-chain-security.md).

## Dependency Policy

The dependency policy lives in `deny.toml`. Unknown registries and git sources
are denied by default. License exceptions must be narrow, named, versioned, and
documented with the reason for acceptance.

Build scripts, procedural macros, `*-sys` crates, vendored native code, Cargo
aliases, CI workflow edits, and release script edits are treated as executable
supply-chain changes. Review them before merging dependency updates.

Reviewed advisory exceptions are allowed only when there is no compatible
upgrade and the affected API is not reachable in Fluxheim. Each exception must
be listed in the tool that reports it (`deny.toml` or `.cargo/audit.toml`), with
a removal condition.

Current reviewed dependency warnings:

- `RUSTSEC-2024-0437` for `protobuf 2.28.0`: transitive through Pingora's
  dependency stack. Fluxheim does not parse protobuf input. Remove the exception
  when Pingora no longer pulls vulnerable protobuf 2.x. The release metadata
  gate also fails after the scheduled manual review date `2026-08-01` while the
  exception remains present.
- `RUSTSEC-2025-0069` for `daemonize 0.5.0`: warning-only unmaintained
  transitive through Pingora. Recheck on every Pingora upgrade.
- `RUSTSEC-2024-0388` for `derivative 2.2.0`: transitive through Pingora's
  dependency stack. It is an unmaintained compile-time derive macro dependency,
  not a Fluxheim runtime request parser. Remove the exception when Pingora no
  longer pulls `derivative`. The release metadata gate also fails after the
  scheduled manual review date `2026-11-01` while the exception remains
  present. This warning is tracked in `.cargo/audit.toml`; cargo-deny currently
  rejects the ignore as unused because it does not classify the advisory for
  this graph.
- `RUSTSEC-2025-0134` for `rustls-pemfile 2.2.0`: warning-only unmaintained
  transitive through Pingora's Rustls stack and `rustls-native-certs`.
  Fluxheim no longer depends on it directly and uses
  `rustls-pki-types::pem::PemObject` for local PEM parsing. Recheck on every
  Pingora or Rustls dependency upgrade.

## Release Supply-Chain Evidence

Stable releases must publish SPDX and CycloneDX SBOM files generated from the
tagged source tree. The release notes must include SBOM checksums, source archive
checksums, binary checksums, container digests, and the signed tag verification
line.

Fluxheim also runs a local reproducible-build check for release candidates. The
check builds the release binary twice from separate target directories with the
same lockfile and compares the resulting executable hash. This is a practical
release-builder reproducibility gate, not a claim that every supported distro or
container builder is bit-for-bit reproducible across machines.

## TLS File Policy

On Unix deployments, private key files should be owner-only (`0600`) and ACME
storage directories should be owner-only (`0700`). Fluxheim's TLS storage helper
checks these permissions separately from config parsing so operators can validate
configuration before certificates are provisioned and then validate filesystem
state before startup or renewal.

Fluxheim's Unix filesystem trust checks inspect ownership, symlinks, and classic
mode bits. They do not parse POSIX extended ACLs yet. Regulated or multi-tenant
deployments should audit sensitive Fluxheim paths with platform tools such as
`getfacl`, keep parent directories private to the service user, and disable
swap/core dumps for processes that handle admin bearer tokens, EAB secrets, TLS
private keys, or cache encryption credentials. The process-local admin token
MAC key is generated at startup and intentionally remains resident for the
process lifetime, so high-assurance deployments should also disable core dumps,
avoid swap, and use service isolation that prevents `/proc/<pid>/mem` access.

```bash
fluxheim --config path/to/fluxheim.toml --check-tls-storage
```

## Reporting

Do not publish exploitable security details before a fix is available. Open a
private security advisory or contact the maintainers directly once the project
has public repository security channels configured.
