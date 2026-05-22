# Rust Supply-Chain Security

Fluxheim treats the Rust dependency graph as part of the trusted computing
base. Rust's memory safety reduces classes of runtime bugs, but it does not
protect against a compromised crate, a malicious build script, a procedural
macro, a poisoned native dependency, or a maintainer account takeover.

This document defines the current supply-chain controls and the hardening
roadmap for Fluxheim release work.

## Current Controls

- `Cargo.lock` is committed and release builds use `--locked`.
- `deny.toml` denies unknown registries, unknown git sources, yanked crates,
  and unknown licenses by default.
- `.cargo/audit.toml` keeps RustSec advisory exceptions explicit and
  versioned.
- GitHub CI runs formatting, clippy, tests, CodeQL, `cargo deny`, `cargo
  audit`, OWASP baseline checks, feature builds, and smoke tests.
- Stable releases generate SPDX and CycloneDX SBOMs from the tagged source
  tree.
- Stable releases record source archive checksums, binary checksums, SBOM
  checksums, signed tag verification, container digests, and reproducible-build
  evidence.

## Build Scripts And Procedural Macros

Cargo build scripts and procedural macros execute code on the build host. Treat
them like native build tools, not like passive source files.

Fluxheim does not rely on a global "disable every dependency build script"
switch. Cargo supports overriding some build scripts for `links` packages and a
package can opt out of its own build script, but stable Cargo does not provide a
single project-wide control that safely disables every transitive build script
and procedural macro while preserving normal builds.

Required review for dependency changes:

- Review every new `build.rs`, procedural macro crate, `*-sys` crate, vendored C
  or assembly source, and native tool invocation.
- Check for environment variable reads, network access, file writes outside
  `OUT_DIR`, generated code, compiler/linker wrapper use, and bundled binaries.
- Prefer system-provided cryptographic modules for regulated profiles, such as
  OpenSSL FIPS provider deployments, over vendored native crypto unless the
  vendor module and build path are explicitly documented.
- Do not build untrusted forks, unreviewed dependency branches, or experimental
  dependency updates in an environment that has release keys, production tokens,
  registry credentials, SSH agents, or cloud credentials.
- Treat `.cargo/config.toml`, Cargo aliases, wrapper scripts, CI workflow
  changes, and release scripts as executable supply-chain changes.

## Dependency Update Workflow

Use `cargo update` only as a deliberate dependency maintenance step.

For each update:

1. Review the `Cargo.lock` diff before running the full test suite.
2. Identify new crates, new major versions, new publishers, new build scripts,
   new proc macros, and new native dependencies.
3. Run `cargo deny check`, `cargo deny check licenses`, and `cargo audit`.
4. Run the relevant feature builds and tests for the changed dependency area.
5. Update `SECURITY.md`, release notes, `deny.toml`, or `.cargo/audit.toml`
   when an advisory exception or license exception changes.

Do not hide dependency churn inside unrelated feature commits.

## Build Isolation

Local development and CI should keep build environments low-trust by default:

- Use rootless containers or a restricted sandbox for dependency experiments,
  untrusted forks, and native build investigation.
- Keep production secrets out of the shell used for `cargo build`, `cargo test`,
  and dependency tooling.
- Do not give pull-request workflows from external forks registry push
  credentials, release signing keys, or production service tokens.
- Keep image publishing and GitHub release publishing on maintainer-triggered
  workflows.

## Human Review Roadmap

Fluxheim should add `cargo-vet` once the 1.3.x security work stabilizes.

Planned adoption path:

1. Initialize a `supply-chain/` directory and commit the generated
   `config.toml`, `audits.toml`, and `imports.lock`.
2. Import only trusted third-party audit sources that are relevant to the
   Fluxheim dependency graph.
3. Start with explicit exemptions for the existing graph so the first
   integration is reviewable.
4. Require human audit entries for new direct dependencies, new proc macros,
   new build scripts, and new native dependencies.
5. Add `cargo vet` to CI after the initial policy is stable and false positives
   are understood.

`cargo-vet` is not a replacement for `cargo-audit` or `cargo-deny`; it adds
human review evidence for code that has no known advisory.

## Embedded Binary Metadata Roadmap

Fluxheim already publishes external SBOM files. A future release should evaluate
`cargo-auditable` or native Rust SBOM embedding for release binaries so scanners
can recover dependency metadata directly from deployed artifacts.

Before enabling embedded metadata by default, validate:

- release reproducibility impact;
- RPM and container build compatibility;
- cross-target behavior;
- interaction with the current SPDX and CycloneDX release evidence.

## Accepted Limitations

- Dependency-level `unsafe` code in networking, TLS, OS, and runtime crates is
  not automatically a vulnerability. It is a review trigger.
- A clean `cargo audit` result only means there is no known RustSec advisory for
  the resolved graph. It does not prove a crate is non-malicious.
- SBOM files improve traceability, but they do not prevent a malicious build.
- FIPS or ISO/IEC 19790 TLS mode constrains cryptographic providers and TLS
  configuration. It does not validate unrelated dependency behavior.
